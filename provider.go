// Package virtualmin implements a DNS record management client compatible
// with the libdns interfaces for Virtualmin/Webmin (BIND-backed DNS zones).
//
// Records are managed via Virtualmin's remote CGI API:
//
//	https://your-server:10000/virtual-server/remote.cgi
//
// The domain managed must exist as a Virtualmin virtual server with DNS
// enabled.  Raw BIND zones not associated with a virtual server are not
// accessible via this API.
//
// Authentication uses HTTP Basic auth with the credentials of a Webmin user
// that has access to the Virtualmin Virtual Servers module and DNS management
// for the target domain.  A Webmin API key (Bearer token) is also supported
// and preferred over username/password.
//
// Minimum supported Virtualmin version: 7.50.0 (fixes TXT record space
// handling, virtualmin/virtualmin-gpl#1104).
//
// # Known limitation: GetRecords TXT value truncation
//
// Virtualmin's get-dns API returns records in a fixed-width plaintext table
// where the value column is 41 characters wide.  Long TXT values (ACME
// challenge tokens are 43 chars, DKIM keys are much longer) are silently
// truncated.  GetRecords therefore cannot return reliable full TXT values.
//
// This does not affect ACME DNS-01 correctness: AppendRecords writes the
// full value, DeleteRecords targets records by name+type (not value), and
// Caddy's ACME solver does not read back the challenge token after writing it.
//
// All methods are safe for concurrent use.
package virtualmin

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

// Provider implements the libdns interfaces for Virtualmin/Webmin.
type Provider struct {
	// ServerURL is the base URL of the Virtualmin/Webmin server including
	// the port.  Example: "https://host.example.com:10000"
	ServerURL string `json:"server_url"`

	// Username is the Webmin user with access to the Virtualmin Virtual
	// Servers module and DNS management for the target domain.
	// Used for HTTP Basic auth when APIKey is not set.
	Username string `json:"username,omitempty"`

	// Password is the Webmin user's password.
	// Used for HTTP Basic auth when APIKey is not set.
	Password string `json:"password,omitempty"`

	// APIKey is a Webmin API key (preferred over Username+Password).
	// When set it is sent as a Bearer token.
	APIKey string `json:"api_key,omitempty"`

	// DomainOverride sets the Virtualmin domain name used for all API calls,
	// regardless of the zone passed by the libdns caller.
	//
	// Use this when the Virtualmin virtual server name does not match the
	// actual DNS zone.  A common case is Virtualmin sub-servers: a virtual
	// server "cert.example.com" may share the zone file of its parent
	// "example.com", so Caddy discovers the zone as "example.com." but the
	// Virtualmin API only knows the records under "cert.example.com".
	//
	// When set, the provider calls modify-dns and get-dns with this domain
	// instead of deriving it from the zone argument.
	//
	// Example: if DomainOverride is "cert.example.com" and Caddy passes zone
	// "example.com.", the provider calls --domain cert.example.com.
	DomainOverride string `json:"domain_override,omitempty"`

	// Insecure disables TLS certificate verification.  Use only when Webmin
	// presents a self-signed certificate.  Not recommended for production.
	Insecure bool `json:"insecure,omitempty"`

	// mu serialises all write operations to avoid concurrent modify-dns
	// calls racing on the same zone's SOA serial.
	mu sync.Mutex
}

// GetRecords returns the DNS records in the given zone.
//
// NOTE: TXT record values longer than 41 characters are truncated by the
// Virtualmin API.  Do not rely on TXT values returned by this method for
// ACME challenge tokens, DKIM keys, or other long strings.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return p.getRecords(ctx, zone)
}

// AppendRecords creates the given records in the zone and returns the records
// that were created.  It never modifies existing records.
func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var created []libdns.Record
	for _, rec := range recs {
		if err := p.appendRecord(ctx, zone, rec); err != nil {
			return created, fmt.Errorf("appending record %q: %w", rec.RR().Name, err)
		}
		created = append(created, rec)
	}
	return created, nil
}

// SetRecords ensures the zone reflects the given records.  For each
// (Name, Type) pair it removes all existing records with that pair and
// replaces them with the supplied records.  Other records are left untouched.
//
// This operation is NOT atomic.
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Collect the (name, type) pairs we need to clear.
	type key struct{ name, typ string }
	desired := make(map[key]struct{})
	for _, rec := range recs {
		rr := rec.RR()
		desired[key{
			name: libdns.AbsoluteName(rr.Name, zone),
			typ:  rr.Type,
		}] = struct{}{}
	}

	// Fetch existing records and delete those matching a desired (name, type).
	existing, err := p.getRecords(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("getting existing records: %w", err)
	}
	for _, ex := range existing {
		rr := ex.RR()
		k := key{libdns.AbsoluteName(rr.Name, zone), rr.Type}
		if _, ok := desired[k]; ok {
			if _, err := p.deleteRecord(ctx, zone, ex); err != nil {
				return nil, fmt.Errorf("deleting old record %q %s: %w", rr.Name, rr.Type, err)
			}
		}
	}

	// Append all desired records.
	var set []libdns.Record
	for _, rec := range recs {
		if err := p.appendRecord(ctx, zone, rec); err != nil {
			return set, fmt.Errorf("setting record %q: %w", rec.RR().Name, err)
		}
		set = append(set, rec)
	}
	return set, nil
}

// DeleteRecords removes the given records from the zone.  Records in the
// input that do not exist are silently ignored.
//
// Matching is by name+type only — the value is NOT used for matching because
// the Virtualmin API truncates long TXT values in get-dns responses.  This
// means DeleteRecords will remove ALL records with the given (name, type),
// regardless of value.  For ACME DNS-01 this is correct behaviour.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var deleted []libdns.Record
	for _, rec := range recs {
		found, err := p.deleteRecord(ctx, zone, rec)
		if err != nil {
			return deleted, fmt.Errorf("deleting record %q: %w", rec.RR().Name, err)
		}
		if found {
			deleted = append(deleted, rec)
		}
	}
	return deleted, nil
}

// ── internal helpers ──────────────────────────────────────────────────────────

// resolveDomain returns the Virtualmin domain name to use for API calls.
// When DomainOverride is set it takes precedence over the zone argument,
// allowing sub-server virtual servers to be targeted regardless of which
// zone Caddy's ACME client discovered as authoritative.
func (p *Provider) resolveDomain(zone string) string {
	if p.DomainOverride != "" {
		return p.DomainOverride
	}
	return zoneToDomain(zone)
}

func (p *Provider) getRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	resp, err := p.callAPI(ctx, "get-dns", map[string]string{
		"domain": p.resolveDomain(zone),
	})
	if err != nil {
		return nil, err
	}
	return parseGetDNSResponse(resp, zone)
}

func (p *Provider) appendRecord(ctx context.Context, zone string, rec libdns.Record) error {
	arg, err := recordToAddArg(rec, zone)
	if err != nil {
		return err
	}
	_, err = p.callAPI(ctx, "modify-dns", map[string]string{
		"domain":              p.resolveDomain(zone),
		"add-record-with-ttl": arg,
	})
	return err
}

// deleteRecord deletes by name+type only.  The value is deliberately omitted
// because Virtualmin truncates long TXT values in get-dns, making value-based
// matching unreliable.  Returns (true, nil) on success, (false, nil) when the
// record did not exist.
func (p *Provider) deleteRecord(ctx context.Context, zone string, rec libdns.Record) (bool, error) {
	arg := recordToDeleteArg(rec, zone)
	_, err := p.callAPI(ctx, "modify-dns", map[string]string{
		"domain":        p.resolveDomain(zone),
		"remove-record": arg,
	})
	if err != nil {
		if isNotFoundError(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ── record format helpers ─────────────────────────────────────────────────────

// zoneToDomain strips the trailing dot libdns zones always carry.
func zoneToDomain(zone string) string {
	return strings.TrimSuffix(zone, ".")
}

// recordToAddArg builds the single whitespace-separated argument for
// modify-dns --add-record-with-ttl: "name TYPE ttl value".
//
// The record name is passed as a fully-qualified domain name with trailing
// dot (e.g. "www.example.com.").  Virtualmin treats any name without a
// trailing dot as relative and appends the domain, which causes double-
// suffixing for multi-label names like "_acme-challenge_foo.sub".
func recordToAddArg(rec libdns.Record, zone string) (string, error) {
	rr := rec.RR()
	name := rrAbsoluteName(rr.Name, zone)
	ttl := int(rr.TTL.Seconds())
	if ttl <= 0 {
		ttl = 3600
	}
	value, err := rrToVirtualminValue(rec)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s %s %d %s", name, rr.Type, ttl, value), nil
}

// recordToDeleteArg builds "name TYPE" for modify-dns --remove-record.
// Uses FQDN with trailing dot for the same reason as recordToAddArg.
// Value is intentionally omitted — see deleteRecord for rationale.
func recordToDeleteArg(rec libdns.Record, zone string) string {
	rr := rec.RR()
	name := rrAbsoluteName(rr.Name, zone)
	if rr.Type == "" {
		return name
	}
	return fmt.Sprintf("%s %s", name, rr.Type)
}

// rrAbsoluteName returns the record name as a fully-qualified domain name
// with a trailing dot, which Virtualmin treats as absolute (no domain suffix
// appended).  This prevents double-suffixing of multi-label names such as
// "_acme-challenge_foo.sub" where Virtualmin would otherwise append the
// domain a second time.
func rrAbsoluteName(name, zone string) string {
	abs := libdns.AbsoluteName(name, zone)
	if !strings.HasSuffix(abs, ".") {
		abs += "."
	}
	return abs
}

// rrRelativeName is retained for use in parseGetDNSResponse where relative
// names are needed for the libdns Record output.
func rrRelativeName(name, zone string) string {
	rel := libdns.RelativeName(libdns.AbsoluteName(name, zone), zone)
	if rel == "" {
		return "@"
	}
	return rel
}

// rrToVirtualminValue converts a libdns.Record to the RDATA string for the
// Virtualmin add-record argument.
func rrToVirtualminValue(rec libdns.Record) (string, error) {
	parsed, err := rec.RR().Parse()
	if err != nil {
		return rec.RR().Data, nil //nolint:nilerr
	}

	switch t := parsed.(type) {
	case libdns.TXT:
		// Do NOT quote — Virtualmin ≥ 7.50.0 adds quotes itself when writing
		// to the BIND zone file.  Quoting here produces double-quoted values
		// (confirmed by live testing: ""value"" in the zone file).
		return t.Text, nil

	case libdns.Address:
		return t.IP.String(), nil

	case libdns.CNAME:
		return fqdnDot(t.Target), nil

	case libdns.MX:
		return fmt.Sprintf("%d %s", t.Preference, fqdnDot(t.Target)), nil

	case libdns.NS:
		return fqdnDot(t.Target), nil

	case libdns.SRV:
		return fmt.Sprintf("%d %d %d %s", t.Priority, t.Weight, t.Port, fqdnDot(t.Target)), nil

	case libdns.CAA:
		escaped := strings.ReplaceAll(t.Value, `"`, `\"`)
		return fmt.Sprintf(`%d %s "%s"`, t.Flags, t.Tag, escaped), nil

	case libdns.RR:
		return t.Data, nil

	default:
		return rec.RR().Data, nil
	}
}

func fqdnDot(name string) string {
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

// ── response parser ───────────────────────────────────────────────────────────

// parseGetDNSResponse converts the fixed-width plaintext rows inside the
// get-dns JSON response into typed libdns.Record values.
//
// The first two rows are always a header and separator line — they are skipped
// automatically by parseRow returning empty strings for non-data rows.
func parseGetDNSResponse(resp *apiResponse, zone string) ([]libdns.Record, error) {
	var records []libdns.Record

	for _, entry := range resp.Data {
		recName, recType, recValue := parseRow(entry.Name)
		if recName == "" || recType == "" {
			continue
		}

		// Make the name relative to the zone.
		// Virtualmin returns names either as bare labels ("www") or FQDNs
		// with a trailing dot ("moren.it.").
		absName := recName
		if !strings.HasSuffix(absName, ".") {
			// Bare label — make it absolute by appending the zone.
			absName = libdns.AbsoluteName(recName, zone)
		}
		relName := libdns.RelativeName(
			strings.TrimSuffix(absName, "."),
			strings.TrimSuffix(zone, "."),
		)
		if relName == "" {
			relName = "@"
		}

		// TTL is not present in the get-dns output — leave as 0.
		rec, err := buildRecord(recType, relName, 0, recValue)
		if err != nil {
			// Skip unrecognised or malformed records.
			continue
		}
		records = append(records, rec)
	}

	return records, nil
}

// buildRecord constructs the appropriate typed libdns.Record.
func buildRecord(recType, relName string, ttl time.Duration, rawValue string) (libdns.Record, error) {
	switch recType {
	case "A", "AAAA":
		ip, err := netip.ParseAddr(rawValue)
		if err != nil {
			return nil, fmt.Errorf("parsing IP %q: %w", rawValue, err)
		}
		return libdns.Address{Name: relName, TTL: ttl, IP: ip}, nil

	case "CNAME":
		return libdns.CNAME{Name: relName, TTL: ttl, Target: rawValue}, nil

	case "NS":
		return libdns.NS{Name: relName, TTL: ttl, Target: rawValue}, nil

	case "TXT":
		// get-dns returns TXT values with surrounding quotes when the value
		// was stored quoted in the zone file (e.g. "value" → returns "value").
		// Strip them so callers get the raw text.
		text := strings.TrimSpace(rawValue)
		if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
			text = text[1 : len(text)-1]
		}
		// Note: value may still be truncated to ~40 chars by the Virtualmin API.
		return libdns.TXT{Name: relName, TTL: ttl, Text: text}, nil

	case "MX":
		parts := strings.SplitN(rawValue, " ", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("malformed MX value %q", rawValue)
		}
		pref, err := strconv.ParseUint(parts[0], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("parsing MX preference %q: %w", parts[0], err)
		}
		return libdns.MX{
			Name:       relName,
			TTL:        ttl,
			Preference: uint16(pref),
			Target:     parts[1],
		}, nil

	case "SRV":
		parts := strings.Fields(rawValue)
		if len(parts) < 4 {
			return nil, fmt.Errorf("malformed SRV value %q", rawValue)
		}
		prio, _ := strconv.ParseUint(parts[0], 10, 16)
		wt, _ := strconv.ParseUint(parts[1], 10, 16)
		port, _ := strconv.ParseUint(parts[2], 10, 16)
		svc, proto, base := parseSRVName(relName)
		return libdns.SRV{
			Service:   svc,
			Transport: proto,
			Name:      base,
			TTL:       ttl,
			Priority:  uint16(prio),
			Weight:    uint16(wt),
			Port:      uint16(port),
			Target:    parts[3],
		}, nil

	case "CAA":
		flags, tag, val, err := parseCAAValue(rawValue)
		if err != nil {
			return nil, fmt.Errorf("parsing CAA value %q: %w", rawValue, err)
		}
		return libdns.CAA{
			Name:  relName,
			TTL:   ttl,
			Flags: flags,
			Tag:   tag,
			Value: val,
		}, nil

	default:
		// SOA, SPF, DNSKEY, RRSIG, etc — return as generic RR.
		return libdns.RR{
			Name: relName,
			TTL:  ttl,
			Type: recType,
			Data: rawValue,
		}, nil
	}
}

// ── small parsers ─────────────────────────────────────────────────────────────

func parseSRVName(name string) (service, proto, base string) {
	if name == "@" || name == "" {
		return "", "", name
	}
	parts := strings.SplitN(name, ".", 3)
	if len(parts) < 2 {
		return "", "", name
	}
	service = strings.TrimPrefix(parts[0], "_")
	proto = strings.TrimPrefix(parts[1], "_")
	if len(parts) == 3 {
		base = parts[2]
	}
	return
}

func parseCAAValue(s string) (flags uint8, tag string, value string, err error) {
	parts := strings.SplitN(s, " ", 3)
	if len(parts) < 3 {
		err = fmt.Errorf("expected 3 fields")
		return
	}
	f, e := strconv.ParseUint(parts[0], 10, 8)
	if e != nil {
		err = fmt.Errorf("flags: %w", e)
		return
	}
	flags = uint8(f)
	tag = parts[1]
	// Strip surrounding quotes if present.
	v := strings.TrimSpace(parts[2])
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	value = strings.ReplaceAll(v, `\"`, `"`)
	return
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such record") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "deleting 0 dns records")
}

// ── interface guards ──────────────────────────────────────────────────────────

var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
