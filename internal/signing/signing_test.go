package signing

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.key")
	pub, err := Generate(path)
	if err != nil {
		t.Fatal(err)
	}
	key, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := []byte(`{"schemaVersion": 1}`)
	sig, gotPub := Sign(key, doc)
	if gotPub != pub {
		t.Errorf("the key file and Generate disagree: %s vs %s", gotPub, pub)
	}
	if err := Verify(pub, sig, doc); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func() error{
		"a changed document": func() error { return Verify(pub, sig, append(doc, ' ')) },
		"another key": func() error {
			other, err := Generate(filepath.Join(t.TempDir(), "o.key"))
			if err != nil {
				return err
			}
			return Verify(other, sig, doc)
		},
		"a garbled signature": func() error { return Verify(pub, "AAAA", doc) },
		"a garbled key":       func() error { return Verify("zz", sig, doc) },
	} {
		if change() == nil {
			t.Errorf("%s verified", name)
		}
	}
	if !strings.HasPrefix(Fingerprint(pub), "SHA256:") || Fingerprint("zz") != "" || Fingerprint("") != "" || Fingerprint("AAAA") != "" {
		t.Errorf("fingerprint %q", Fingerprint(pub))
	}
}

// A signature is for hostlint results: the same bytes signed for another purpose do not verify.
func TestSignaturesAreDomainSeparated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k")
	pub, _ := Generate(path)
	key, _ := Load(path)
	sig, _ := Sign(key, []byte("x"))
	// Verify the raw bytes without the domain: it must fail. (Verify adds the domain itself.)
	if err := Verify(pub, sig, []byte("hostlint result v1\nx")); err == nil {
		t.Error("a signature of the document verified for the document with the domain in it")
	}
}

func TestKeyFilesAreProtected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k")
	if _, err := Generate(path); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	if _, err := Generate(path); err == nil || !strings.Contains(err.Error(), "never overwritten") {
		t.Errorf("a key was overwritten: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "read by other users") {
		t.Errorf("a group-readable key was loaded: %v", err)
	}
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Error("garbage was loaded as a key")
	}
	if _, err := Load(dir); err == nil {
		t.Error("a directory was loaded as a key")
	}
}
