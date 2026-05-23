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

// apiResponse is the top-level JSON structure returned by remote.cgi when
// the json=1 parameter is set.
//
// Virtualmin's json-lib.pl converts the multiline text output of each
// program into a structured JSON tree.  For get-dns the shape is:
//
//	{
//	  "status": "success",
//	  "data": [
//	    {
//	      "name": "www.example.com.",
//	      "values": {
//	        "type":  ["A"],
//	        "class": ["IN"],
//	        "ttl":   ["3600"],
//	        "value": ["192.0.2.1"]
//	      }
//	    },
//	    ...
//	  ]
//	}
//
// Every value inside "values" is always a []string, even for singletons.
type apiResponse struct {
	Status string       `json:"status"`
	Error  string       `json:"error,omitempty"`
	Data   []dataRecord `json:"data"`
}

// dataRecord is one element of the "data" array returned by get-dns.
// The "name" field is the DNS record's FQDN (with trailing dot).
// The "values" map holds the record attributes; keys are lowercased and
// spaces replaced with underscores by Virtualmin's JSON shim.
type dataRecord struct {
	Name   string              `json:"name"`
	Values map[string][]string `json:"values"`
}

// ── HTTP client management ────────────────────────────────────────────────────

var (
	defaultClientOnce sync.Once
	defaultClient     *http.Client
)

// httpClient returns the provider's own http.Client when set via the
// unexported field (used in tests), or a lazily-created shared default.
// The default client respects the Insecure flag on the provider.
func (p *Provider) httpClient() *http.Client {
	// Build a per-provider client when TLS verification is disabled, so we
	// do not poison the shared default.
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

// callAPI calls a Virtualmin remote API program and returns the parsed JSON
// response.
//
// program is the Virtualmin program name, e.g. "get-dns" or "modify-dns".
// params is a map of additional CGI parameters (without the "program" key).
//
// The call always requests JSON output (json=1) and uses multiline=1 for
// list-style programs so that Virtualmin's JSON shim has structured data to
// parse.
//
// Authentication precedence:
//  1. APIKey  → Authorization: Bearer <key>
//  2. Username + Password → HTTP Basic auth
func (p *Provider) callAPI(ctx context.Context, program string, params map[string]string) (*apiResponse, error) {
	if p.ServerURL == "" {
		return nil, fmt.Errorf("virtualmin: ServerURL must not be empty")
	}

	// Build query string.
	query := url.Values{}
	query.Set("program", program)
	query.Set("json", "1")
	for k, v := range params {
		query.Set(k, v)
	}

	endpoint := strings.TrimSuffix(p.ServerURL, "/") + "/virtual-server/remote.cgi"

	// Use POST to avoid sensitive data appearing in server logs / URLs.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(query.Encode()))
	if err != nil {
		return nil, fmt.Errorf("virtualmin: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Set auth.
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

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("virtualmin: authentication failed (HTTP %d) — check credentials and Webmin ACLs", resp.StatusCode)
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
			// Some Virtualmin versions embed the error in data[0].name.
			if len(parsed.Data) > 0 {
				msg = parsed.Data[0].Name
			}
		}
		if msg == "" {
			msg = "unknown error"
		}
		return nil, fmt.Errorf("virtualmin: API error for program %q: %s", program, msg)
	}

	return &parsed, nil
}

// truncate returns at most n bytes of s for use in error messages.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
