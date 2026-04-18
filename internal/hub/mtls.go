// Package hub implements hub-side gateway services. This file provides the
// mTLS certificate authority that signs client certificates for edge nodes
// (proxy, door, local) per the P1 design's "Edge -> Hub" auth model.
//
// The CA is a single self-signed ECDSA P-256 root. Edges present a CSR via
// the admin API; the hub validates the CSR, binds the resulting certificate
// to a node_id (CommonName) and node_type (URI SAN), and signs it. Peer
// verification extracts the same two values from a presented peer cert and
// rejects any cert whose serial is in the hub's in-memory CRL.
//
// All persistence is stdlib only: PEM files for the root cert/key, and a
// single plaintext serial counter file under data_dir. CRL state is
// in-memory only — P1 does not persist revocations across restarts (the
// design leaves rotation/persistence to P3).
package hub

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SAN URI scheme used by hub-signed client certs.
//
// Rationale: x509 has no first-class "role" attribute. Overloading OU is
// lossy (no multi-value, often truncated by tools). A private OID custom
// extension is another option but harder to read at a glance with openssl.
// A URI SAN in a custom scheme ("gateway:node-type:<type>") is stdlib-
// native, round-trips cleanly through x509.Certificate.URIs, and makes
// "what is this cert for?" obvious in a hex dump. The same scheme is used
// for the node-id URI ("gateway:node-id:<id>") so the full identity lives
// in SAN, with CN kept for operator-readability.
const (
	sanSchemeGateway = "gateway"
	sanNodeIDHost    = "node-id"
	sanNodeTypeHost  = "node-type"
)

// CA carries the hub's signing root and the in-memory revocation list.
// The zero value is not usable — construct with NewCA.
type CA struct {
	// rootCert is the self-signed root. Exported via CertPool() for use
	// in server tls.Config's ClientCAs.
	rootCert *x509.Certificate
	// rootKey signs issued certs and the CRL.
	rootKey *ecdsa.PrivateKey

	// dataDir holds the serial counter file. Empty when a caller builds
	// a CA in-memory (tests). When empty, SignCSR still works but the
	// counter is process-local only.
	dataDir string

	// mu guards nextSerial, revoked, and the serial-file on disk. One
	// mutex is sufficient: signing is not a hot path (edge registration
	// is rare) and the CRL/revocation ops are infrequent.
	mu         sync.Mutex
	nextSerial *big.Int
	revoked    map[string]revokedEntry // key: serial.Text(10)
}

type revokedEntry struct {
	serial *big.Int
	when   time.Time
}

// Default root validity and subject. Ten years matches the P1 spec; the
// CA is rotated by rerunning install-hub.sh, not by code.
const (
	rootValidity = 10 * 365 * 24 * time.Hour
	rootSubjectCN = "gateway hub CA"
)

// NewCA loads or generates the hub's root CA.
//
// Files are treated as an atomic pair: both present -> load; both absent
// -> generate and write with 0600; exactly one present -> error, because
// a half-installed CA almost certainly indicates a partial install or a
// file deletion and silently regenerating would invalidate every
// previously-issued client cert.
//
// The data directory for the serial counter is derived from certFile's
// parent. Callers that want an explicit path can set it via SetDataDir
// (tests do this).
func NewCA(certFile, keyFile string) (*CA, error) {
	certExists := fileExists(certFile)
	keyExists := fileExists(keyFile)

	switch {
	case certExists && keyExists:
		return loadCA(certFile, keyFile)
	case !certExists && !keyExists:
		return generateCA(certFile, keyFile)
	default:
		return nil, fmt.Errorf("hub/mtls: inconsistent CA files: cert=%v key=%v", certExists, keyExists)
	}
}

// SetDataDir points the CA at a directory for its serial counter. The
// directory is created if missing. Must be called before the first
// SignCSR in processes that persist serials across restarts.
func (c *CA) SetDataDir(dir string) error {
	if dir == "" {
		return fmt.Errorf("hub/mtls: empty data dir")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("hub/mtls: mkdir data_dir %q: %w", dir, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.dataDir = dir
	// Reload the counter from disk if present. If the file is malformed
	// we surface the error — silently resetting would collide old serials.
	loaded, err := readSerial(filepath.Join(dir, "serial"))
	if err != nil {
		return err
	}
	if loaded != nil && loaded.Cmp(c.nextSerial) > 0 {
		c.nextSerial = loaded
	}
	return nil
}

func loadCA(certFile, keyFile string) (*CA, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("hub/mtls: read cert %q: %w", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("hub/mtls: read key %q: %w", keyFile, err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("hub/mtls: %q is not a PEM CERTIFICATE", certFile)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("hub/mtls: parse cert: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("hub/mtls: %q is not a PEM block", keyFile)
	}
	var key *ecdsa.PrivateKey
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		var k any
		k, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err == nil {
			var ok bool
			key, ok = k.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("hub/mtls: key %q is not ECDSA", keyFile)
			}
		}
	default:
		return nil, fmt.Errorf("hub/mtls: key %q has unexpected PEM type %q", keyFile, keyBlock.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("hub/mtls: parse key: %w", err)
	}

	ca := newCAStruct(cert, key)
	// Derive dataDir from cert file parent. Best-effort; tests override.
	if parent := filepath.Dir(certFile); parent != "" {
		if loaded, rerr := readSerial(filepath.Join(parent, "serial")); rerr == nil && loaded != nil {
			if loaded.Cmp(ca.nextSerial) > 0 {
				ca.nextSerial = loaded
			}
			ca.dataDir = parent
		}
	}
	return ca, nil
}

func generateCA(certFile, keyFile string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("hub/mtls: generate key: %w", err)
	}

	// The root's own serial is random per the x509 SerialNumber
	// uniqueness requirement; issued-cert serials use the monotonic
	// counter below.
	rootSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("hub/mtls: root serial: %w", err)
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			CommonName: rootSubjectCN,
		},
		NotBefore:             now.Add(-1 * time.Minute), // tolerate slight clock skew
		NotAfter:              now.Add(rootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // forbid sub-CAs; edges are leaf-only
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("hub/mtls: self-sign root: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("hub/mtls: re-parse root: %w", err)
	}

	if err := writePEMFile(certFile, "CERTIFICATE", der, 0o600); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("hub/mtls: marshal key: %w", err)
	}
	if err := writePEMFile(keyFile, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		// Leave cert file in place — caller sees both-present on retry
		// and would then fail loud because key load will fail too; we
		// don't silently delete files we just wrote.
		return nil, err
	}

	ca := newCAStruct(cert, key)
	// data_dir defaults to cert's parent so the installer doesn't have
	// to wire it separately.
	ca.dataDir = filepath.Dir(certFile)
	return ca, nil
}

// newCAStruct is the common initializer used by load and generate paths.
func newCAStruct(cert *x509.Certificate, key *ecdsa.PrivateKey) *CA {
	return &CA{
		rootCert:   cert,
		rootKey:    key,
		nextSerial: big.NewInt(1),
		revoked:    make(map[string]revokedEntry),
	}
}

// CertPool returns an *x509.CertPool containing only the root certificate.
// Hub HTTP servers pass this pool as tls.Config.ClientCAs.
func (c *CA) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.rootCert)
	return pool
}

// RootCert returns the parsed root certificate. Useful for install-time
// CA-bundle export over HTTP.
func (c *CA) RootCert() *x509.Certificate { return c.rootCert }

// IssueServerCert mints a fresh TLS server certificate signed by this CA.
// It is separate from SignCSR because server certs need ExtKeyUsageServerAuth
// and DNS/IP SANs rather than the node-id/node-type URI SANs that SignCSR
// bakes into client certs.
//
// commonName populates Subject.CN (operator-readability only). dnsNames and
// ipAddrs populate SAN; at least one SAN entry is required for modern TLS
// verifiers to accept the cert. validity bounds the cert lifetime; the
// caller is responsible for choosing a value appropriate to their rotation
// policy (gateway-hub issues on every start, so it picks a long value).
//
// Returns a tls.Certificate ready for tls.Config.Certificates.
func (c *CA) IssueServerCert(commonName string, dnsNames []string, ipAddrs []net.IP, validity time.Duration) (tls.Certificate, error) {
	if len(dnsNames) == 0 && len(ipAddrs) == 0 {
		return tls.Certificate{}, fmt.Errorf("hub/mtls: server cert requires at least one SAN entry")
	}
	if validity <= 0 {
		return tls.Certificate{}, fmt.Errorf("hub/mtls: validity must be positive, got %s", validity)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("hub/mtls: generate server key: %w", err)
	}

	serial, err := c.allocateSerial()
	if err != nil {
		return tls.Certificate{}, err
	}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-1 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     append([]string(nil), dnsNames...),
		IPAddresses:  append([]net.IP(nil), ipAddrs...),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.rootCert, &key.PublicKey, c.rootKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("hub/mtls: sign server cert: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}

// SignCSR parses a PEM-encoded CSR, verifies it, and issues a client
// certificate bound to nodeID and nodeType.
//
// Invariants enforced on the CSR:
//   - PEM type "CERTIFICATE REQUEST"
//   - Self-signature is valid (CSR's PublicKey matches the signature)
//   - CommonName == nodeID (nodeID is the authoritative identifier; CN
//     duplicates it for operator-readability but the installer must set
//     them equal)
//   - nodeType is one of the accepted constants (proxy, door, local)
//
// The issued certificate has:
//   - Subject.CommonName = nodeID
//   - ExtKeyUsage = ClientAuth (never ServerAuth)
//   - KeyUsage = DigitalSignature (minimum for TLS client handshake)
//   - URI SANs: gateway:node-id:<nodeID> and gateway:node-type:<nodeType>
//   - Serial from the monotonic counter (see nextSerialLocked)
//
// Returns DER (not PEM) so callers can wrap however they like.
func (c *CA) SignCSR(csrBytes []byte, nodeID, nodeType string, validity time.Duration) ([]byte, *big.Int, error) {
	if nodeID == "" {
		return nil, nil, errors.New("hub/mtls: nodeID is required")
	}
	if !validNodeType(nodeType) {
		return nil, nil, fmt.Errorf("hub/mtls: invalid nodeType %q", nodeType)
	}
	if validity <= 0 {
		return nil, nil, fmt.Errorf("hub/mtls: validity must be positive, got %s", validity)
	}

	block, _ := pem.Decode(csrBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("hub/mtls: CSR must be a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("hub/mtls: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("hub/mtls: CSR signature: %w", err)
	}
	if csr.Subject.CommonName != nodeID {
		return nil, nil, fmt.Errorf("hub/mtls: CSR CN %q does not match nodeID %q",
			csr.Subject.CommonName, nodeID)
	}

	nodeIDURI := &url.URL{Scheme: sanSchemeGateway, Opaque: sanNodeIDHost + ":" + nodeID}
	nodeTypeURI := &url.URL{Scheme: sanSchemeGateway, Opaque: sanNodeTypeHost + ":" + nodeType}

	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: nodeID,
		},
		NotBefore:   now.Add(-1 * time.Minute),
		NotAfter:    now.Add(validity),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        []*url.URL{nodeIDURI, nodeTypeURI},
	}

	serial, err := c.allocateSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl.SerialNumber = serial

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.rootCert, csr.PublicKey, c.rootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("hub/mtls: sign: %w", err)
	}
	return der, serial, nil
}

// Revoke marks serial as revoked. Idempotent: repeated revocations of the
// same serial update the "when" timestamp but do not create duplicates in
// the generated CRL.
func (c *CA) Revoke(serial *big.Int) error {
	if serial == nil {
		return errors.New("hub/mtls: nil serial")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revoked[serial.Text(10)] = revokedEntry{
		serial: new(big.Int).Set(serial),
		when:   time.Now().UTC(),
	}
	return nil
}

// BuildCRL returns a DER-encoded CRL signed by the root. The CRL has a
// one-hour ThisUpdate/NextUpdate window — edges are expected to poll every
// 60s per the design; one hour gives ample grace for clock skew without
// letting a stale list linger.
func (c *CA) BuildCRL() ([]byte, error) {
	c.mu.Lock()
	list := make([]x509.RevocationListEntry, 0, len(c.revoked))
	for _, e := range c.revoked {
		list = append(list, x509.RevocationListEntry{
			SerialNumber:   new(big.Int).Set(e.serial),
			RevocationTime: e.when,
		})
	}
	c.mu.Unlock()

	now := time.Now().UTC()
	tmpl := &x509.RevocationList{
		Issuer:                    c.rootCert.Subject,
		ThisUpdate:                now,
		NextUpdate:                now.Add(1 * time.Hour),
		Number:                    big.NewInt(now.Unix()),
		RevokedCertificateEntries: list,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, c.rootCert, c.rootKey)
	if err != nil {
		return nil, fmt.Errorf("hub/mtls: create CRL: %w", err)
	}
	return der, nil
}

// IsRevoked reports whether serial is in the CRL. Exposed separately from
// VerifyPeer so hub admin endpoints can check without constructing a TLS
// ConnectionState.
func (c *CA) IsRevoked(serial *big.Int) bool {
	if serial == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.revoked[serial.Text(10)]
	return ok
}

// VerifyPeer inspects a completed TLS handshake's peer certificates,
// confirms the leaf was signed by this CA, and extracts its nodeID and
// nodeType from the SAN URIs.
//
// Callers typically invoke this inside an HTTP middleware after
// tls.Config has already enforced ClientAuth. The extra check here
// guards against misconfigured servers and also implements the CRL
// check, which tls.Config does not do for us.
func (c *CA) VerifyPeer(state *tls.ConnectionState) (nodeID, nodeType string, err error) {
	if state == nil {
		return "", "", errors.New("hub/mtls: nil ConnectionState")
	}
	if len(state.PeerCertificates) == 0 {
		return "", "", errors.New("hub/mtls: no peer certificates")
	}
	leaf := state.PeerCertificates[0]

	// Belt-and-braces signature check. When tls.Config already validated
	// the chain with our pool, this is redundant but cheap; when a test
	// or misconfigured server skipped verification, it's the last line.
	if err := leaf.CheckSignatureFrom(c.rootCert); err != nil {
		return "", "", fmt.Errorf("hub/mtls: leaf not signed by hub CA: %w", err)
	}

	if c.IsRevoked(leaf.SerialNumber) {
		return "", "", fmt.Errorf("hub/mtls: certificate serial %s is revoked", leaf.SerialNumber)
	}

	nodeID, nodeType, err = extractIdentity(leaf)
	if err != nil {
		return "", "", err
	}
	return nodeID, nodeType, nil
}

// allocateSerial returns the next serial under lock, persists the new
// counter to disk when a data_dir is configured, and increments.
//
// Errors from the disk write abort the issuance entirely — we do not
// want a signed cert whose serial was handed out but not persisted,
// because a crash between sign and persist would recycle the serial
// on restart.
func (c *CA) allocateSerial() (*big.Int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	serial := new(big.Int).Set(c.nextSerial)
	next := new(big.Int).Add(c.nextSerial, big.NewInt(1))

	if c.dataDir != "" {
		if err := writeSerial(filepath.Join(c.dataDir, "serial"), next); err != nil {
			return nil, err
		}
	}
	c.nextSerial = next
	return serial, nil
}

// extractIdentity pulls nodeID and nodeType from the SAN URIs of a
// cert issued by this CA. Both URIs must be present; a cert that has
// only one is malformed.
func extractIdentity(cert *x509.Certificate) (nodeID, nodeType string, err error) {
	for _, u := range cert.URIs {
		if u == nil || u.Scheme != sanSchemeGateway {
			continue
		}
		host, value, ok := strings.Cut(u.Opaque, ":")
		if !ok {
			continue
		}
		switch host {
		case sanNodeIDHost:
			nodeID = value
		case sanNodeTypeHost:
			nodeType = value
		}
	}
	if nodeID == "" {
		return "", "", errors.New("hub/mtls: leaf missing gateway:node-id SAN")
	}
	if nodeType == "" {
		return "", "", errors.New("hub/mtls: leaf missing gateway:node-type SAN")
	}
	// Cross-check CN vs SAN. CN is advisory but setting the two to
	// disagree is always a mistake.
	if cert.Subject.CommonName != "" && cert.Subject.CommonName != nodeID {
		return "", "", fmt.Errorf("hub/mtls: CN %q disagrees with SAN node-id %q",
			cert.Subject.CommonName, nodeID)
	}
	return nodeID, nodeType, nil
}

// validNodeType accepts the P1 node-type strings. "hub" is deliberately
// not here: the hub does not issue a client cert to itself.
func validNodeType(t string) bool {
	switch t {
	case "proxy", "door", "local":
		return true
	}
	return false
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// writePEMFile writes a single PEM block atomically-ish (write + rename
// would be safer, but install scripts run under an exclusive /etc/gateway
// and os.WriteFile with explicit 0600 is adequate for P1).
func writePEMFile(path, pemType string, der []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("hub/mtls: mkdir %q: %w", filepath.Dir(path), err)
	}
	block := &pem.Block{Type: pemType, Bytes: der}
	buf := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, buf, mode); err != nil {
		return fmt.Errorf("hub/mtls: write %q: %w", path, err)
	}
	// os.WriteFile on Windows ignores the mode beyond read-only bits;
	// a best-effort Chmod afterwards covers the Unix case where the
	// umask of the calling process stripped group/other perms already.
	_ = os.Chmod(path, mode)
	return nil
}

// readSerial reads the monotonic counter. Returns nil,nil if the file is
// absent (fresh install). Returns an error only on read/parse failure of
// an existing file.
func readSerial(path string) (*big.Int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("hub/mtls: read serial %q: %w", path, err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil, nil
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("hub/mtls: parse serial %q: %w", path, err)
	}
	return new(big.Int).SetUint64(n), nil
}

// writeSerial writes n to path with 0600. Callers hold c.mu so there is
// no concurrent write race on the same file.
func writeSerial(path string, n *big.Int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("hub/mtls: mkdir %q: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(n.String()+"\n"), 0o600); err != nil {
		return fmt.Errorf("hub/mtls: write serial %q: %w", path, err)
	}
	_ = os.Chmod(path, 0o600)
	return nil
}
