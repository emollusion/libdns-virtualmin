package virtualmin_test

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
	"github.com/emollusion/libdns-virtualmin"
)

// Integration tests require a live Virtualmin server.  Set the following
// environment variables to run them:
//
//	TEST_VIRTUALMIN_URL      e.g. https://vps.example.com:10000
//	TEST_VIRTUALMIN_USER     e.g. root
//	TEST_VIRTUALMIN_PASS     e.g. s3cr3t
//	TEST_VIRTUALMIN_API_KEY  (alternative to user+pass)
//	TEST_ZONE                e.g. example.com.  (trailing dot required)
//
// Tests are skipped automatically when TEST_ZONE or the URL is absent.

func newProvider(t *testing.T) *virtualmin.Provider {
	t.Helper()
	serverURL := os.Getenv("TEST_VIRTUALMIN_URL")
	zone := os.Getenv("TEST_ZONE")
	if serverURL == "" || zone == "" {
		t.Skip("skipping integration test: TEST_VIRTUALMIN_URL and TEST_ZONE must be set")
	}

	return &virtualmin.Provider{
		ServerURL: serverURL,
		Username:  os.Getenv("TEST_VIRTUALMIN_USER"),
		Password:  os.Getenv("TEST_VIRTUALMIN_PASS"),
		APIKey:    os.Getenv("TEST_VIRTUALMIN_API_KEY"),
		Insecure:  os.Getenv("TEST_VIRTUALMIN_INSECURE") == "1",
	}
}

func testZone(t *testing.T) string {
	t.Helper()
	z := os.Getenv("TEST_ZONE")
	if z == "" {
		t.Skip("TEST_ZONE not set")
	}
	return z
}

// TestGetRecords verifies that GetRecords returns at least the SOA/NS records
// that every zone always has.
func TestGetRecords(t *testing.T) {
	p := newProvider(t)
	zone := testZone(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	recs, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	if len(recs) == 0 {
		t.Fatal("GetRecords returned no records; expected at least NS/SOA")
	}
	t.Logf("GetRecords returned %d records", len(recs))
	for _, r := range recs {
		rr := r.RR()
		t.Logf("  %-30s %-8s %v  %s", rr.Name, rr.Type, rr.TTL, rr.Data)
	}
}

// TestTXTRoundTrip appends a TXT record, verifies it appears in GetRecords,
// then deletes it and verifies it is gone.
func TestTXTRoundTrip(t *testing.T) {
	p := newProvider(t)
	zone := testZone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rec := libdns.TXT{
		Name: "_libdns-test",
		TTL:  60 * time.Second,
		Text: "libdns virtualmin test record",
	}

	// Append.
	appended, err := p.AppendRecords(ctx, zone, []libdns.Record{rec})
	if err != nil {
		t.Fatalf("AppendRecords: %v", err)
	}
	if len(appended) != 1 {
		t.Fatalf("expected 1 appended record, got %d", len(appended))
	}
	t.Logf("Appended: %v", appended[0].RR())

	// Cleanup: always attempt deletion, even if later assertions fail.
	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dcancel()
		if _, err := p.DeleteRecords(dctx, zone, []libdns.Record{rec}); err != nil {
			t.Logf("cleanup delete: %v", err)
		}
	})

	// Verify it appears in GetRecords.
	allRecs, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords after append: %v", err)
	}
	found := false
	for _, r := range allRecs {
		if txt, ok := r.(libdns.TXT); ok {
			if txt.Name == rec.Name && txt.Text == rec.Text {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("appended TXT record not found in GetRecords output")
	}

	// Delete.
	deleted, err := p.DeleteRecords(ctx, zone, []libdns.Record{rec})
	if err != nil {
		t.Fatalf("DeleteRecords: %v", err)
	}
	if len(deleted) == 0 {
		t.Fatal("DeleteRecords reported 0 deleted records")
	}
	t.Logf("Deleted %d record(s)", len(deleted))

	// Verify it is gone.
	allRecs2, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords after delete: %v", err)
	}
	for _, r := range allRecs2 {
		if txt, ok := r.(libdns.TXT); ok {
			if txt.Name == rec.Name && txt.Text == rec.Text {
				t.Error("TXT record still present after delete")
			}
		}
	}
}

// TestSetRecords verifies that SetRecords replaces an existing TXT RRset.
func TestSetRecords(t *testing.T) {
	p := newProvider(t)
	zone := testZone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	name := "_libdns-set-test"

	initial := libdns.TXT{Name: name, TTL: 60 * time.Second, Text: "initial-value"}
	replacement := libdns.TXT{Name: name, TTL: 60 * time.Second, Text: "replaced-value"}

	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dcancel()
		p.DeleteRecords(dctx, zone, []libdns.Record{initial, replacement}) //nolint:errcheck
	})

	// Create initial record.
	if _, err := p.AppendRecords(ctx, zone, []libdns.Record{initial}); err != nil {
		t.Fatalf("AppendRecords (initial): %v", err)
	}

	// Replace with SetRecords.
	if _, err := p.SetRecords(ctx, zone, []libdns.Record{replacement}); err != nil {
		t.Fatalf("SetRecords: %v", err)
	}

	// Verify only the replacement exists.
	allRecs, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords after SetRecords: %v", err)
	}

	var foundInitial, foundReplacement bool
	for _, r := range allRecs {
		if txt, ok := r.(libdns.TXT); ok && txt.Name == name {
			if txt.Text == initial.Text {
				foundInitial = true
			}
			if txt.Text == replacement.Text {
				foundReplacement = true
			}
		}
	}
	if foundInitial {
		t.Error("initial TXT record still present after SetRecords — expected it to be replaced")
	}
	if !foundReplacement {
		t.Error("replacement TXT record not found after SetRecords")
	}
}

// TestAddressRecord verifies append/delete for an A record.
func TestAddressRecord(t *testing.T) {
	p := newProvider(t)
	zone := testZone(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rec := libdns.Address{
		Name: "libdns-test-a",
		TTL:  60 * time.Second,
		IP:   netip.MustParseAddr("192.0.2.99"),
	}

	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dcancel()
		p.DeleteRecords(dctx, zone, []libdns.Record{rec}) //nolint:errcheck
	})

	if _, err := p.AppendRecords(ctx, zone, []libdns.Record{rec}); err != nil {
		t.Fatalf("AppendRecords A: %v", err)
	}

	allRecs, err := p.GetRecords(ctx, zone)
	if err != nil {
		t.Fatalf("GetRecords after A append: %v", err)
	}
	found := false
	for _, r := range allRecs {
		if addr, ok := r.(libdns.Address); ok {
			if addr.Name == rec.Name && addr.IP == rec.IP {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("A record not found in GetRecords output after append")
	}

	if _, err := p.DeleteRecords(ctx, zone, []libdns.Record{rec}); err != nil {
		t.Fatalf("DeleteRecords A: %v", err)
	}
}
