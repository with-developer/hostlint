package engine

import "testing"

// The host ID is an HMAC of the machine ID under this key. It keeps the name the project had before it was renamed
// (ADR 0017): a different key gives every machine a second host ID, and the server refuses a known host name that
// comes with another ID. A search and replace of the old name must not change it.
func TestHostIDKeyIsFrozen(t *testing.T) {
	if string(hostIDKey) != "hostlint host id v1" {
		t.Errorf("host ID key = %q", hostIDKey)
	}
}
