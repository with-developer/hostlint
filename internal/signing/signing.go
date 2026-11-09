// Package signing signs scan results with an Ed25519 key kept on the scanned host, and verifies them
// (docs/adr/0010-fleet-server-and-dashboard.md). A signed result is evidence that the document is
// what that host's key sent, even if the server that stores it is later compromised.
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
)

// Header names of a signed push.
const (
	HeaderSignature = "X-Hostlint-Signature"
	HeaderKey       = "X-Hostlint-Key"
)

// context separates these signatures from any other use of the key.
const domain = "hostlint result v1\n"

func message(doc []byte) []byte { return append([]byte(domain), doc...) }

// Sign signs a result document.
func Sign(key ed25519.PrivateKey, doc []byte) (sig, pub string) {
	s := ed25519.Sign(key, message(doc))
	p := key.Public().(ed25519.PublicKey)
	return base64.StdEncoding.EncodeToString(s), base64.StdEncoding.EncodeToString(p)
}

// Verify checks a signature (base64) of doc against a public key (base64).
func Verify(pub, sig string, doc []byte) error {
	p, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(p) != ed25519.PublicKeySize {
		return errors.New("the public key is not an Ed25519 key in base64")
	}
	s, err := base64.StdEncoding.DecodeString(sig)
	if err != nil || len(s) != ed25519.SignatureSize {
		return errors.New("the signature is not an Ed25519 signature in base64")
	}
	if !ed25519.Verify(p, message(doc), s) {
		return errors.New("the signature does not verify")
	}
	return nil
}

// Fingerprint names a public key (base64) the way `ssh-keygen -l` does: SHA256:<base64>.
func Fingerprint(pub string) string {
	p, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(p) != ed25519.PublicKeySize {
		return "" // no key, or not one: no fingerprint
	}
	sum := sha256.Sum256(p)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// Generate makes a key and writes its private half to path (PEM, mode 0600; the file must not
// exist). It returns the public key in base64.
func Generate(path string) (pub string, err error) {
	publicKey, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:forbidigo,gosec // the key file the user named, not the scanned host (G304)
	if errors.Is(err, fs.ErrExist) {
		return "", fmt.Errorf("%s exists: a key is never overwritten", path)
	}
	if err != nil {
		return "", err
	}
	// A key file that was not written completely is removed, so that a retry is not refused.
	werr := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if werr == nil {
		werr = f.Sync() // on disk before the public key is printed and registered
	}
	if err := werr; err != nil {
		_ = f.Close()
		_ = os.Remove(path) //nolint:forbidigo // the file this call made
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path) //nolint:forbidigo // the file this call made
		return "", err
	}
	return base64.StdEncoding.EncodeToString(publicKey), nil
}

// Load reads a private key written by Generate. A key file that other users can read is refused:
// whoever has the key can sign as this host.
func Load(path string) (ed25519.PrivateKey, error) {
	f, err := os.Open(path) //nolint:forbidigo,gosec // the key file the user named, not the scanned host (G304)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat() // the mode of the file that is read, not of one the path may name a moment later
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s can be read by other users (mode %04o): run chmod 600 on it", path, fi.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s is not a vmsctl signing key (made with: vmsctl key generate)", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an Ed25519 key", path)
	}
	return priv, nil
}
