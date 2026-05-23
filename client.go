package virtualmin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ── JSON response types ───────────────────────────────────────────────────────

// apiResponse is the top-level JSON envelope returned by remote.cgi with
// json=1.  The actual record data lives in Data[].Name as a fixed-width
// plaintext string — Virtualmin does NOT return structured per-field JSON for
// get-dns.
//
// Real response shape (confirmed against Virtualmin 7.x):
//
//	{
//	  "status":  "success",
//	  "command": "get-dns",
//	  "data": [
//	    { "name": "Record                         Type  Value                                   ", "values": {} },
//	    { "name": "------------------------------ ----- ----------------------------------------", "values": {} },
//	    { "name": "moren.it.                      NS    ns01.moren.it.                          ", "values": {} },
//	    { "name": "_acme-challenge                TXT   dGVzdC10b2tlbi12YWx1ZS1mb3ItYWNtZQ     ", "values": {} },
//	    ...
//	  ]
//	}
//
// Column layout (total 77 chars per row):
//
//	[record-name: cols 0-29][type: cols 30-35][value: cols 36-76, right-padded]
//
// IMPORTANT: the value column is only 41 characters wide.  Long TXT values
// (e.g. ACME challenge tokens, DKIM keys) are truncated.  This means
// GetRecords cannot reliably return full TXT values — callers must not depend
// on TXT value accuracy from GetRecords.  DeleteRecords targets records by
// name+type only, which is sufficient for all libdns use cases including ACME.
type apiResponse struct {
	Status   string       `json:"status"`
	Error    string       `json:"error,omitempty"`
	FullError string      `json:"full_error,omitempty"`
	Data     []dataRecord `json:"data"`
}

// dataRecord is one row in the data array.  Only Name is meaningful;
// Values is always an empty object {} in get-dns responses.
type dataRecord struct {
	Name string `json:"name"`
}

// ── fixed-width column offsets (confirmed by live measurement) ────────────────

const (
	colNameEnd  = 30 // record name occupies cols [0, 30)
	colTypeEnd  = 36 // type occupies cols [30, 36) — 5 chars + 1 space
	colValueEnd = 77 // value occupies cols [36, 77) — right-padded with spaces
)

// parseRow splits one fixed-width data row into (name, type, value).
// Returns ("", "", "") for header/separator rows and empty rows.
func parseRow(row string) (recName, recType, recValue string) {
	if len(row) < colTypeEnd {
		return "", "", ""
	}
	recName = strings.TrimSpace(row[:colNameEnd])
	recType = strings.TrimSpace(row[colNameEnd:colTypeEnd])

	if len(row) >= colValueEnd {
		recValue = strings.TrimRight(row[colTypeEnd:colValueEnd], " ")
	} else if len(row) > colTypeEnd {
		recValue = strings.TrimRight(row[colTypeEnd:], " ")
	}

	// Skip header and separator rows.
	if recType == "Type" || strings.HasPrefix(recType, "-") {
		return "", "", ""
	}
	// Skip rows with no type (blank lines, continuations).
	if recType == "" {
		return "", "", ""
	}
	return recName, recType, recValue
}

// ── HTTP client management ────────────────────────────────────────────────────

var (
	defaultClientOnce sync.Once
	defaultClient     *http.Client
)

// httpClient returns a per-provider client when Insecure is set (to avoid
// poisoning the shared default), otherwise returns the shared default.
func (p *Provider) httpClient() *http.Client {
	if p.Insecure {
		return &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		}
	}
	defaultClientOnce.Do(func() {
		defaultClient = &http.Client{Timeout: 30 * time.Second}
	})
	return defaultClient
}

// ── Core API call ─────────────────────────────────────────────────────────────

// callAPI POSTs to Virtualmin's remote.cgi and returns the parsed JSON
// response.
//
// Notes from live testing:
//   - multiline=1 is rejected by remote.cgi ("Unknown parameter 1") — do NOT send it.
//   - The Content-type response header is application/json even though the
//     body contains fixed-width plaintext inside the JSON data array.
//   - On auth failure the server returns an HTML page (200 OK) rather than a
//     4xx; we detect this by checking whether the body starts with '{'.
//
// Authentication precedence:
//  1. APIKey  → Authorization: Bearer <key>
//  2. Username + Password → HTTP Basic auth
func (p *Provider) callAPI(ctx context.Context, program string, params map[string]string) (*apiResponse, error) {
	if p.ServerURL == "" {
		return nil, fmt.Errorf("virtualmin: ServerURL must not be empty")
	}

	query := url.Values{}
	query.Set("program", program)
	query.Set("json", "1")
	for k, v := range params {
		query.Set(k, v)
	}

	endpoint := strings.TrimSuffix(p.ServerURL, "/") + "/virtual-server/remote.cgi"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(query.Encode()))
	if err != nil {
		return nil, fmt.Errorf("virtualmin: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	if p.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+p.APIKey)
	} else if p.Username != "" {
		req.SetBasicAuth(p.Username, p.Password)
	} else {
		return nil, fmt.Errorf("virtualmin: no credentials configured (set APIKey or Username+Password)")
	}

	resp, err := p.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("virtualmin: HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("virtualmin: reading response body: %w", err)
	}

	// Auth failures return a 200 HTML page, not a 4xx.
	if len(body) == 0 || body[0] != '{' {
		return nil, fmt.Errorf("virtualmin: unexpected non-JSON response (check credentials and Webmin ACLs); body: %s", truncate(string(body), 200))
	}

	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("virtualmin: server error (HTTP %d): %s", resp.StatusCode, truncate(string(body), 200))
	}

	var parsed apiResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("virtualmin: decoding JSON response: %w (body: %s)", err, truncate(string(body), 200))
	}

	if strings.ToLower(parsed.Status) != "success" {
		msg := parsed.Error
		if msg == "" {
			msg = parsed.FullError
		}
		if msg == "" {
			msg = "unknown error"
		}
		return nil, fmt.Errorf("virtualmin: API error for %q: %s", program, msg)
	}

	return &parsed, nil
}

// truncate returns at most n bytes of s, for use in error messages.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
