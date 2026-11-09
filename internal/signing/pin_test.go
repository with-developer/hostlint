package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// These names and the domain are written into signatures and onto the wire: they keep the names the project had
// before it was renamed (ADR 0017). A search and replace of the old name must not change them, or every stored
// signature stops verifying and an old agent stops talking to a new server.
func TestSignedNamesAreFrozen(t *testing.T) {
	if domain != "hostlint result v1\n" {
		t.Errorf("signing domain = %q", domain)
	}
	if HeaderSignature != "X-Hostlint-Signature" || HeaderKey != "X-Hostlint-Key" {
		t.Errorf("headers = %q, %q", HeaderSignature, HeaderKey)
	}
}

// A known key signs a known document to a known signature: the bytes that were signed before the rename still verify.
func TestKnownSignatureStillVerifies(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	pub := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	sig, gotPub := Sign(key, []byte(`{"a":1}`))
	if gotPub != pub {
		t.Fatalf("public key = %q", gotPub)
	}
	const want = "xyPeszjC3perF+6WBVSZLRQmDRYlf4Q6yraP0SafAvT4ktP9zCWLuqJSPOfSBMdFAV40SrYv41FCrg1T73kNBg=="
	if sig != want {
		t.Errorf("signature = %q, want %q", sig, want)
	}
	if err := Verify(pub, want, []byte(`{"a":1}`)); err != nil {
		t.Errorf("a signature made before the rename: %v", err)
	}
}
