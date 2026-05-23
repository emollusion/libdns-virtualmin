// Package virtualmin implements a DNS record management client compatible
// with the libdns interfaces for Virtualmin/Webmin (BIND-backed DNS zones).
//
// Records are managed via Virtualmin's remote CGI API:
//
//	https://your-server:10000/virtual-server/remote.cgi
//
// Authentication uses HTTP Basic auth with the Webmin master administrator
// credentials (root or admin), or a Webmin API key passed as a Bearer token.
//
// The minimum supported Virtualmin version is 7.50.0, which fixes the
// handling of TXT records containing spaces (issue #1104).
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
// Credentials are supplied either as Username+Password (HTTP Basic auth)
// or as APIKey (Webmin API key, sent as a Bearer token).  If both are set,
// APIKey takes precedence.
type Provider struct {
	// ServerURL is the base URL of the Virtualmin/Webmin server,
	// including the port.  Example: "https://host.example.com:10000"
	ServerURL string `json:"server_url"`

	// Username is the Webmin master administrator username (e.g. "root").
	// Used for HTTP Basic authentication when APIKey is not set.
	Username string `json:"username,omitempty"`

	// Password is the Webmin master administrator password.
	// Used for HTTP Basic authentication when APIKey is not set.
	Password string `json:"password,omitempty"`

	// APIKey is a Webmin API key.  When set it is sent as a Bearer token
	// and Username/Password are ignored.
	APIKey string `json:"api_key,omitempty"`

	// Insecure disables TLS certificate verification.  Enable only when
	// Webmin is using a self-signed certificate and you cannot install a
	// trusted CA.  Do NOT use in production without understanding the risks.
	Insecure bool `json:"insecure,omitempty"`

	// mu serialises write operations per-provider instance.  Virtualmin's
	// BIND writer is not safe under concurrent modify-dns invocations for
	// the same zone, and a single mutex is simpler than a per-zone map for
	// the typical single-zone use case.
	mu sync.Mutex
}

// GetRecords returns all DNS records in the given zone.
//
// The zone must be a fully-qualified domain name with a trailing dot,
// e.g. "example.com."
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
			return created, fmt.Errorf("appending record %v: %w", rec.RR().Name, err)
		}
		created = append(created, rec)
	}
	return created, nil
}

// SetRecords ensures the zone reflects the given records.  For each
// (Name, Type) pair in the input it removes all existing records with that
// pair and replaces them with the supplied records.  Other records in the
// zone are left untouched.
//
// This operation is NOT atomic: if it fails partway through, the zone may
// be in a partially-updated state.
func (p *Provider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Gather all existing records once.
	existing, err := p.getRecords(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("getting existing records: %w", err)
	}

	// Index desired records by (absName, TYPE).
	type key struct{ name, typ string }
	desired := make(map[key][]libdns.Record)
	for _, rec := range recs {
		rr := rec.RR()
		k := key{libdns.AbsoluteName(rr.Name, zone), rr.Type}
		desired[k] = append(desired[k], rec)
	}

	// Delete existing records whose (name, type) matches a desired key.
	for _, ex := range existing {
		rr := ex.RR()
		k := key{libdns.AbsoluteName(rr.Name, zone), rr.Type}
		if _, ok := desired[k]; ok {
			if _, err := p.deleteRecord(ctx, zone, ex); err != nil {
				return nil, fmt.Errorf("deleting old record %v %v: %w", rr.Name, rr.Type, err)
			}
		}
	}

	// Append all desired records.
	var set []libdns.Record
	for _, rec := range recs {
		if err := p.appendRecord(ctx, zone, rec); err != nil {
			return set, fmt.Errorf("setting record %v: %w", rec.RR().Name, err)
		}
		set = append(set, rec)
	}
	return set, nil
}

// DeleteRecords removes the given records from the zone and returns the
// records that were deleted.  Records in the input that do not exist in the
// zone are silently ignored.
//
// Matching follows the libdns contract: Name is always required; Type, TTL,
// and value act as additional filters when non-empty.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var deleted []libdns.Record
	for _, rec := range recs {
		found, err := p.deleteRecord(ctx, zone, rec)
		if err != nil {
			return deleted, fmt.Errorf("deleting record %v: %w", rec.RR().Name, err)
		}
		if found {
			deleted = append(deleted, rec)
		}
	}
	return deleted, nil
}

// getRecords fetches all DNS records for zone from the Virtualmin API and
// converts them to typed libdns.Record values.
func (p *Provider) getRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	domain := zoneToDomain(zone)

	resp, err := p.callAPI(ctx, "get-dns", map[string]string{
		"domain":    domain,
		"multiline": "1",
	})
	if err != nil {
		return nil, err
	}

	return parseGetDNSResponse(resp, zone)
}

// appendRecord adds a single record to the zone via modify-dns --add-record-with-ttl.
func (p *Provider) appendRecord(ctx context.Context, zone string, rec libdns.Record) error {
	domain := zoneToDomain(zone)
	arg, err := recordToAddArg(rec, zone)
	if err != nil {
		return err
	}

	_, err = p.callAPI(ctx, "modify-dns", map[string]string{
		"domain":              domain,
		"add-record-with-ttl": arg,
	})
	return err
}

// deleteRecord removes a single record from the zone via modify-dns
// --remove-record.  It returns (true, nil) when the record existed and was
// deleted, (false, nil) when it did not exist, and (false, err) on API error.
func (p *Provider) deleteRecord(ctx context.Context, zone string, rec libdns.Record) (found bool, _ error) {
	domain := zoneToDomain(zone)
	arg, err := recordToDeleteArg(rec, zone)
	if err != nil {
		return false, err
	}

	resp, err := p.callAPI(ctx, "modify-dns", map[string]string{
		"domain":        domain,
		"remove-record": arg,
	})
	if err != nil {
		// Virtualmin returns an error when the record does not exist.
		// Treat "not found"-style messages as a soft miss rather than an error.
		if isNotFoundError(err) {
			return false, nil
		}
		return false, err
	}
	_ = resp
	return true, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

// zoneToDomain strips the trailing dot from a libdns zone string to produce
// the plain domain name Virtualmin expects.
func zoneToDomain(zone string) string {
	return strings.TrimSuffix(zone, ".")
}

// recordToAddArg builds the single whitespace-separated string that
// modify-dns --add-record-with-ttl expects: "name TYPE ttl value...".
//
// The record name is made relative to the zone so Virtualmin appends the
// domain correctly.  The apex is represented as "@".
func recordToAddArg(rec libdns.Record, zone string) (string, error) {
	rr := rec.RR()

	name := rrRelativeName(rr.Name, zone)
	ttl := int(rr.TTL.Seconds())
	if ttl <= 0 {
		ttl = 3600 // sensible default
	}

	value, err := rrToVirtualminValue(rec, zone)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s %s %d %s", name, rr.Type, ttl, value), nil
}

// recordToDeleteArg builds the string for modify-dns --remove-record:
// "name TYPE [value]".  Including the value is important when multiple
// records share the same (name, type) — e.g. multiple TXT or MX records.
func recordToDeleteArg(rec libdns.Record, zone string) (string, error) {
	rr := rec.RR()
	name := rrRelativeName(rr.Name, zone)

	if rr.Type == "" {
		// Wildcard delete by name only — Virtualmin will remove all records
		// with this name.  This matches the libdns contract for an empty Type.
		return name, nil
	}

	value, err := rrToVirtualminValue(rec, zone)
	if err != nil {
		return "", err
	}

	if value == "" {
		return fmt.Sprintf("%s %s", name, rr.Type), nil
	}
	return fmt.Sprintf("%s %s %s", name, rr.Type, value), nil
}

// rrRelativeName converts a libdns record name (which may already be relative,
// absolute FQDN, or "@") into the relative form that Virtualmin expects.
// An empty result or zone-apex is returned as "@".
func rrRelativeName(name, zone string) string {
	rel := libdns.RelativeName(libdns.AbsoluteName(name, zone), zone)
	if rel == "" {
		return "@"
	}
	return rel
}

// rrToVirtualminValue converts a libdns.Record to the RDATA string portion
// of a Virtualmin add/delete record argument.
func rrToVirtualminValue(rec libdns.Record, zone string) (string, error) {
	// Use the typed parse of RR so we can extract structured fields.
	parsed, err := rec.RR().Parse()
	if err != nil {
		// Fall back to raw RR.Data for unknown types.
		return rec.RR().Data, nil //nolint:nilerr
	}

	switch t := parsed.(type) {
	case libdns.TXT:
		// Wrap value in double-quotes so Virtualmin's BIND writer stores it
		// correctly.  Any embedded double-quotes are backslash-escaped.
		escaped := strings.ReplaceAll(t.Text, `"`, `\"`)
		return fmt.Sprintf(`"%s"`, escaped), nil

	case libdns.Address:
		return t.IP.String(), nil

	case libdns.CNAME:
		return fqdnDot(t.Target), nil

	case libdns.MX:
		return fmt.Sprintf("%d %s", t.Preference, fqdnDot(t.Target)), nil

	case libdns.NS:
		return fqdnDot(t.Target), nil

	case libdns.SRV:
		// SRV name is stored separately in SRV.Name; the value is the RDATA.
		return fmt.Sprintf("%d %d %d %s", t.Priority, t.Weight, t.Port, fqdnDot(t.Target)), nil

	case libdns.CAA:
		escaped := strings.ReplaceAll(t.Value, `"`, `\"`)
		return fmt.Sprintf(`%d %s "%s"`, t.Flags, t.Tag, escaped), nil

	case libdns.RR:
		// Unknown or unsupported type — pass RDATA verbatim.
		return t.Data, nil

	default:
		// Fallback: use the RR serialisation.
		return rec.RR().Data, nil
	}
}

// fqdnDot ensures a domain name ends with a dot (fully qualified).
func fqdnDot(name string) string {
	if !strings.HasSuffix(name, ".") {
		return name + "."
	}
	return name
}

// parseGetDNSResponse converts the JSON response from get-dns into a slice
// of typed libdns.Record values.
func parseGetDNSResponse(resp *apiResponse, zone string) ([]libdns.Record, error) {
	var records []libdns.Record

	for _, entry := range resp.Data {
		// The JSON shim wraps every attribute value in a []string, even
		// singletons.  entry.Values is a map[string][]string.
		if entry.Values == nil {
			continue
		}

		recType := firstVal(entry.Values["type"])
		if recType == "" {
			continue
		}
		recType = strings.ToUpper(recType)

		// Convert the FQDN record name to a libdns relative name.
		relName := libdns.RelativeName(strings.TrimSuffix(entry.Name, "."), strings.TrimSuffix(zone, "."))
		if relName == "" {
			relName = "@"
		}

		ttl := parseTTL(firstVal(entry.Values["ttl"]))

		// There may be multiple Value lines for the same record block.
		values := entry.Values["value"]
		if len(values) == 0 {
			continue
		}

		for _, rawValue := range values {
			rec, err := buildRecord(recType, relName, ttl, rawValue, zone)
			if err != nil {
				// Skip unrecognised/malformed records rather than aborting.
				continue
			}
			records = append(records, rec)
		}
	}

	return records, nil
}

// buildRecord constructs the appropriate typed libdns.Record for a given
// DNS record type and raw RDATA string from Virtualmin.
func buildRecord(recType, relName string, ttl time.Duration, rawValue, zone string) (libdns.Record, error) {
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
		// Virtualmin returns TXT values wrapped in double-quotes from the zone
		// file.  Strip them and unescape embedded quotes.
		text := stripTXTQuotes(rawValue)
		return libdns.TXT{Name: relName, TTL: ttl, Text: text}, nil

	case "MX":
		// Virtualmin returns MX as "preference target".
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
		// SRV RDATA: "priority weight port target"
		// SRV name format: "_service._proto.name"
		parts := strings.Fields(rawValue)
		if len(parts) < 4 {
			return nil, fmt.Errorf("malformed SRV value %q", rawValue)
		}
		prio, _ := strconv.ParseUint(parts[0], 10, 16)
		wt, _ := strconv.ParseUint(parts[1], 10, 16)
		port, _ := strconv.ParseUint(parts[2], 10, 16)

		// Parse _service._proto out of the record name.
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
		// CAA RDATA: "flags tag \"value\""
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
		// Return unknown types as a generic RR so callers can still inspect them.
		return libdns.RR{
			Name: relName,
			TTL:  ttl,
			Type: recType,
			Data: rawValue,
		}, nil
	}
}

// stripTXTQuotes removes surrounding double-quotes from a TXT record value
// as stored in a BIND zone file and unescapes embedded \" sequences.
func stripTXTQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	return strings.ReplaceAll(s, `\"`, `"`)
}

// parseTTL converts a TTL string (seconds as integer) to a time.Duration.
// Returns 0 when the string is empty or unparseable.
func parseTTL(s string) time.Duration {
	if s == "" {
		return 0
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return time.Duration(n) * time.Second
}

// firstVal returns the first element of a string slice, or "" when empty.
func firstVal(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}

// parseSRVName splits an SRV record name of the form "_service._proto[.base]"
// into its three components.  Leading underscores are stripped from service
// and proto to match the libdns.SRV convention.
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
	return service, proto, base
}

// parseCAAValue parses a CAA RDATA string of the form: flags tag "value"
func parseCAAValue(s string) (flags uint8, tag string, value string, err error) {
	// fields: [flags, tag, "value..."]
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
	value = stripTXTQuotes(parts[2])
	return
}

// isNotFoundError returns true when the Virtualmin API error indicates that
// the record to be deleted was not present in the zone.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such record") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "does not exist")
}

// ── interface guards ──────────────────────────────────────────────────────────

var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
