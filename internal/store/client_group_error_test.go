package store

import (
	"context"
	"testing"
)

// A mapping read that fails is not the same as "this client has no mapping".
// The old code treated both as a miss and fell through to the default group,
// so a broken client_mappings table silently judged every mapped client under
// the wrong policy while GetGroupForClient still returned (default, nil).
func TestGetGroupForClientSurfacesMappingReadFailures(t *testing.T) {
	cases := []struct {
		name            string
		clientID        string
		clientIDTrusted bool
	}{
		{name: "ip mapping", clientID: "", clientIDTrusted: false},
		{name: "client_id mapping", clientID: "my-tablet", clientIDTrusted: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			ctx := context.Background()

			// Dropping the table leaves client_groups intact, so the old
			// fall-through would still find and return the default group.
			if _, err := db.db.ExecContext(ctx, "DROP TABLE client_mappings"); err != nil {
				t.Fatalf("drop mapping table: %v", err)
			}

			group, err := db.GetGroupForClient(ctx, "192.168.1.50", tc.clientID, tc.clientIDTrusted)
			if err == nil {
				t.Fatalf("a failed mapping read must not resolve to %+v without an error", group)
			}
		})
	}
}
