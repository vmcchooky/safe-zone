package risk

import (
	"context"
	"testing"
)

// TestUntrustedClientIDCannotPickGroup pins the anti-spoofing contract at the
// pipeline level: resolveClientGroup hardcodes clientIDTrusted=false
// (internal/risk/analysis_pipeline.go), so a DoH caller presenting a
// client_id that is mapped to a stricter group must stay under the group its
// trusted IP resolves to. The store-level rejection is separately table-
// tested (TestGetGroupForClient); this test would fail if the hardcoded
// false were ever flipped to true.
func TestUntrustedClientIDCannotPickGroup(t *testing.T) {
	service := newTestServiceWithStore(t)
	db := service.StoreDB()

	kidsID, err := db.CreateGroup(context.Background(), "kids", "Kids group", []string{"social_media"}, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddMappingInt(context.Background(), "client_id", "device-kids", kidsID); err != nil {
		t.Fatal(err)
	}
	devsID, err := db.CreateGroup(context.Background(), "devs", "Devs group", []string{}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.AddMappingInt(context.Background(), "ip", "192.0.2.99", devsID); err != nil {
		t.Fatal(err)
	}

	// The spoof attempt: a caller inside the devs IP mapping presents the
	// client_id that would place it in the (stricter) kids group.
	spoofed := service.Policy(context.Background(), "facebook.com",
		ClientInfo{IP: "192.0.2.99", ClientID: "device-kids"})
	if spoofed.Policy != "allow" {
		t.Fatalf("spoofed client_id changed the group: facebook.com = %s for the devs IP, want allow", spoofed.Policy)
	}

	// The same IP without any client_id must resolve identically.
	plain := service.Policy(context.Background(), "facebook.com",
		ClientInfo{IP: "192.0.2.99"})
	if plain.Policy != spoofed.Policy {
		t.Fatalf("client_id presence changed the decision: %s vs %s", plain.Policy, spoofed.Policy)
	}

	// Control: a caller whose IP maps into kids is genuinely under the kids
	// group (the mapping machinery works; only the client_id axis is gated).
	if _, err := db.AddMappingInt(context.Background(), "ip", "198.51.100.7", kidsID); err != nil {
		t.Fatal(err)
	}
	legit := service.Policy(context.Background(), "facebook.com",
		ClientInfo{IP: "198.51.100.7", ClientID: "unrelated-device"})
	if legit.Policy != "block" {
		t.Fatalf("IP-mapped kids caller got %s for facebook.com, want block", legit.Policy)
	}
}
