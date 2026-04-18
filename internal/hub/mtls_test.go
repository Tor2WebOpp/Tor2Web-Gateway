package hub

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// helper: make a temp CA backed by real files.
func newTestCA(t *testing.T) (*CA, string, string) {
	t.Helper()
	dir := t.TempDir()
	cert := filepath.Join(dir, "hub-ca.pem")
	key := filepath.Join(dir, "hub-ca.key")
	ca, err := NewCA(cert, key)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	if err := ca.SetDataDir(dir); err != nil {
		t.Fatalf("SetDataDir: %v", err)
	}
	return ca, cert, key
}

// helper: generate a CSR for (nodeID).
func makeCSR(t *testing.T, nodeID string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: nodeID}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	return pemBytes, key
}

func TestNewCAGenerateThenLoad(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.pem")
	key := filepath.Join(dir, "ca.key")

	// First call: generates.
	ca1, err := NewCA(cert, key)
	if err != nil {
		t.Fatalf("first NewCA: %v", err)
	}
	if ca1.rootCert == nil || ca1.rootKey == nil {
		t.Fatal("root not populated after generate")
	}
	if !ca1.rootCert.IsCA {
		t.Fatal("root cert IsCA must be true")
	}
	if !ca1.rootCert.BasicConstraintsValid {
		t.Fatal("BasicConstraintsValid must be true")
	}
	if ca1.rootCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatal("root missing KeyUsageCertSign")
	}
	if ca1.rootCert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		t.Fatal("root missing KeyUsageCRLSign")
	}
	if ca1.rootCert.Subject.CommonName != "gateway hub CA" {
		t.Fatalf("unexpected CN: %q", ca1.rootCert.Subject.CommonName)
	}
	// Validity window: 10 years.
	if got := ca1.rootCert.NotAfter.Sub(ca1.rootCert.NotBefore); got < 9*365*24*time.Hour {
		t.Fatalf("root validity too short: %s", got)
	}
	// ECDSA P-256.
	if _, ok := ca1.rootCert.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("root pubkey not ECDSA: %T", ca1.rootCert.PublicKey)
	}

	// File perms. Windows os.WriteFile does not honor unix perms fully,
	// so the check below is only meaningful on unix. On Windows we just
	// require the files to exist.
	for _, path := range []string{cert, key} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %q: %v", path, err)
		}
		if runtime.GOOS != "windows" {
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("file %q mode %v, want 0600", path, info.Mode().Perm())
			}
		}
	}

	// Second call: both files exist -> load, fingerprint match.
	ca2, err := NewCA(cert, key)
	if err != nil {
		t.Fatalf("second NewCA: %v", err)
	}
	if !ca2.rootCert.Equal(ca1.rootCert) {
		t.Fatal("loaded CA does not match generated root")
	}
}

func TestNewCAInconsistentFiles(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.pem")
	key := filepath.Join(dir, "ca.key")

	// Only cert exists.
	if err := os.WriteFile(cert, []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCA(cert, key); err == nil {
		t.Fatal("want error when only cert exists")
	} else if !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("want inconsistent error, got %v", err)
	}

	// Only key exists.
	if err := os.Remove(cert); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("dummy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewCA(cert, key); err == nil {
		t.Fatal("want error when only key exists")
	}
}

func TestSignCSRHappyPath(t *testing.T) {
	ca, _, _ := newTestCA(t)
	csrPEM, _ := makeCSR(t, "edge-7a3c")

	der, serial, err := ca.SignCSR(csrPEM, "edge-7a3c", "proxy", 24*time.Hour)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if serial == nil || serial.Sign() <= 0 {
		t.Fatalf("serial must be positive, got %v", serial)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse signed cert: %v", err)
	}

	if cert.Subject.CommonName != "edge-7a3c" {
		t.Fatalf("CN = %q, want edge-7a3c", cert.Subject.CommonName)
	}
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("ExtKeyUsage = %v, want [ClientAuth]", cert.ExtKeyUsage)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Fatal("leaf missing KeyUsageDigitalSignature")
	}

	// SAN URIs contain the node-type marker.
	var foundType, foundID bool
	for _, u := range cert.URIs {
		s := u.String()
		if strings.Contains(s, "node-type:proxy") {
			foundType = true
		}
		if strings.Contains(s, "node-id:edge-7a3c") {
			foundID = true
		}
	}
	if !foundType {
		t.Fatalf("SAN missing node-type URI; got %v", cert.URIs)
	}
	if !foundID {
		t.Fatalf("SAN missing node-id URI; got %v", cert.URIs)
	}

	// Verifies against the CA pool.
	opts := x509.VerifyOptions{
		Roots:     ca.CertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Fatalf("cert verify: %v", err)
	}
}

func TestSignCSRCNMismatch(t *testing.T) {
	ca, _, _ := newTestCA(t)
	csrPEM, _ := makeCSR(t, "not-the-node")

	_, _, err := ca.SignCSR(csrPEM, "edge-7a3c", "proxy", time.Hour)
	if err == nil {
		t.Fatal("want error for CN != nodeID")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want CN-mismatch error, got %v", err)
	}
}

func TestSignCSRInvalidNodeType(t *testing.T) {
	ca, _, _ := newTestCA(t)
	csrPEM, _ := makeCSR(t, "edge-7a3c")
	if _, _, err := ca.SignCSR(csrPEM, "edge-7a3c", "hub", time.Hour); err == nil {
		t.Fatal("want error for nodeType=hub")
	}
	if _, _, err := ca.SignCSR(csrPEM, "edge-7a3c", "", time.Hour); err == nil {
		t.Fatal("want error for empty nodeType")
	}
	if _, _, err := ca.SignCSR(csrPEM, "edge-7a3c", "bogus", time.Hour); err == nil {
		t.Fatal("want error for nodeType=bogus")
	}
}

func TestSignCSRInvalidPEM(t *testing.T) {
	ca, _, _ := newTestCA(t)
	if _, _, err := ca.SignCSR([]byte("not-pem"), "x", "proxy", time.Hour); err == nil {
		t.Fatal("want error for non-PEM input")
	}
	wrongType := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")})
	if _, _, err := ca.SignCSR(wrongType, "x", "proxy", time.Hour); err == nil {
		t.Fatal("want error for wrong PEM type")
	}
}

func TestRevokeAndCRLContainsSerial(t *testing.T) {
	ca, _, _ := newTestCA(t)
	csrPEM, _ := makeCSR(t, "edge-dead")
	_, serial, err := ca.SignCSR(csrPEM, "edge-dead", "proxy", time.Hour)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	if err := ca.Revoke(serial); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	crlDER, err := ca.BuildCRL()
	if err != nil {
		t.Fatalf("BuildCRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	if err := crl.CheckSignatureFrom(ca.rootCert); err != nil {
		t.Fatalf("CRL sig: %v", err)
	}

	found := false
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(serial) == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("CRL does not contain serial %v; entries=%v", serial, crl.RevokedCertificateEntries)
	}

	// Idempotent revoke — second call same serial does not create a duplicate.
	if err := ca.Revoke(serial); err != nil {
		t.Fatalf("Revoke second: %v", err)
	}
	crl2DER, err := ca.BuildCRL()
	if err != nil {
		t.Fatalf("BuildCRL second: %v", err)
	}
	crl2, _ := x509.ParseRevocationList(crl2DER)
	count := 0
	for _, e := range crl2.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(serial) == 0 {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate serial in CRL: count=%d", count)
	}
}

func TestVerifyPeerAcceptsValid(t *testing.T) {
	ca, _, _ := newTestCA(t)
	csrPEM, _ := makeCSR(t, "edge-7a3c")
	der, _, err := ca.SignCSR(csrPEM, "edge-7a3c", "proxy", time.Hour)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)

	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	id, typ, err := ca.VerifyPeer(state)
	if err != nil {
		t.Fatalf("VerifyPeer: %v", err)
	}
	if id != "edge-7a3c" {
		t.Fatalf("nodeID = %q, want edge-7a3c", id)
	}
	if typ != "proxy" {
		t.Fatalf("nodeType = %q, want proxy", typ)
	}
}

func TestVerifyPeerRejectsRevoked(t *testing.T) {
	ca, _, _ := newTestCA(t)
	csrPEM, _ := makeCSR(t, "edge-burn")
	der, serial, err := ca.SignCSR(csrPEM, "edge-burn", "proxy", time.Hour)
	if err != nil {
		t.Fatalf("SignCSR: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	if err := ca.Revoke(serial); err != nil {
		t.Fatal(err)
	}
	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if _, _, err := ca.VerifyPeer(state); err == nil {
		t.Fatal("want error for revoked cert")
	} else if !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("want revoked error, got %v", err)
	}
}

func TestVerifyPeerRejectsForeignCert(t *testing.T) {
	ca, _, _ := newTestCA(t)

	// Build a cert signed by a different CA entirely.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "other root"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		BasicConstraintsValid: true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &otherKey.PublicKey, otherKey)
	rootCert, _ := x509.ParseCertificate(rootDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "edge-7a3c"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, rootCert, &leafKey.PublicKey, otherKey)
	leaf, _ := x509.ParseCertificate(leafDER)

	state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if _, _, err := ca.VerifyPeer(state); err == nil {
		t.Fatal("want error for foreign cert")
	}
}

func TestVerifyPeerNoCerts(t *testing.T) {
	ca, _, _ := newTestCA(t)
	if _, _, err := ca.VerifyPeer(nil); err == nil {
		t.Fatal("want error for nil state")
	}
	if _, _, err := ca.VerifyPeer(&tls.ConnectionState{}); err == nil {
		t.Fatal("want error for empty PeerCertificates")
	}
}

func TestCertPool(t *testing.T) {
	ca, _, _ := newTestCA(t)
	pool := ca.CertPool()
	if pool == nil {
		t.Fatal("nil pool")
	}
	// Issue a cert and verify it in the pool end-to-end.
	csrPEM, _ := makeCSR(t, "edge-1")
	der, _, err := ca.SignCSR(csrPEM, "edge-1", "local", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	opts := x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := cert.Verify(opts); err != nil {
		t.Fatalf("cert verify via CertPool: %v", err)
	}
}

func TestConcurrentSignCSRProducesUniqueSerials(t *testing.T) {
	ca, _, _ := newTestCA(t)

	const n = 50
	csrs := make([][]byte, n)
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		ids[i] = "edge-" + strconv.Itoa(i)
		csrs[i], _ = makeCSR(t, ids[i])
	}

	type result struct {
		serial *big.Int
		err    error
	}
	results := make(chan result, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, s, err := ca.SignCSR(csrs[i], ids[i], "proxy", time.Hour)
			results <- result{s, err}
		}()
	}
	wg.Wait()
	close(results)

	seen := make(map[string]bool, n)
	max := big.NewInt(0)
	min := new(big.Int).SetUint64(^uint64(0))
	for r := range results {
		if r.err != nil {
			t.Fatalf("concurrent SignCSR: %v", r.err)
		}
		k := r.serial.Text(10)
		if seen[k] {
			t.Fatalf("duplicate serial %s", k)
		}
		seen[k] = true
		if r.serial.Cmp(max) > 0 {
			max.Set(r.serial)
		}
		if r.serial.Cmp(min) < 0 {
			min.Set(r.serial)
		}
	}
	if len(seen) != n {
		t.Fatalf("want %d unique serials, got %d", n, len(seen))
	}
	// Monotonic: every serial is between min and max, and since each is
	// unique and they're consecutive integers from the counter, max-min
	// must equal n-1.
	diff := new(big.Int).Sub(max, min)
	if diff.Cmp(big.NewInt(int64(n-1))) != 0 {
		t.Fatalf("serials not consecutive: min=%s max=%s diff=%s want=%d",
			min, max, diff, n-1)
	}
}

// Serial counter persists across load/generate cycles. Specifically, if we
// sign a cert, then build a new CA struct from the same files, the next
// serial must exceed all previously-issued ones.
func TestSerialPersistsAcrossReload(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "ca.pem")
	key := filepath.Join(dir, "ca.key")

	ca, err := NewCA(cert, key)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	if err := ca.SetDataDir(dir); err != nil {
		t.Fatalf("SetDataDir: %v", err)
	}
	var lastSerial *big.Int
	for i := 0; i < 5; i++ {
		csrPEM, _ := makeCSR(t, "edge-"+strconv.Itoa(i))
		_, s, err := ca.SignCSR(csrPEM, "edge-"+strconv.Itoa(i), "proxy", time.Hour)
		if err != nil {
			t.Fatalf("SignCSR: %v", err)
		}
		lastSerial = s
	}

	// Reload and sign again. New serial must be strictly greater than
	// anything from the first round.
	ca2, err := NewCA(cert, key)
	if err != nil {
		t.Fatalf("reload NewCA: %v", err)
	}
	if err := ca2.SetDataDir(dir); err != nil {
		t.Fatalf("reload SetDataDir: %v", err)
	}
	csrPEM, _ := makeCSR(t, "edge-new")
	_, s, err := ca2.SignCSR(csrPEM, "edge-new", "proxy", time.Hour)
	if err != nil {
		t.Fatalf("SignCSR after reload: %v", err)
	}
	if s.Cmp(lastSerial) <= 0 {
		t.Fatalf("serial went backwards after reload: last=%v now=%v", lastSerial, s)
	}
}

func TestIsRevoked(t *testing.T) {
	ca, _, _ := newTestCA(t)
	if ca.IsRevoked(big.NewInt(123)) {
		t.Fatal("unknown serial should not be revoked")
	}
	if ca.IsRevoked(nil) {
		t.Fatal("nil serial must not report revoked")
	}
	_ = ca.Revoke(big.NewInt(123))
	if !ca.IsRevoked(big.NewInt(123)) {
		t.Fatal("revoked serial must report true")
	}
}
