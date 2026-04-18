package hub

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"gateway/internal/shared"
)

// Node validity used for the lifetime of a freshly-signed client cert.
// 365d matches the P1 spec. Rotation is out of scope for P1 (owner re-runs
// install.sh, hub revokes the old serial, issues a new one).
const nodeCertValidity = 365 * 24 * time.Hour

// NodeRecord is the canonical in-memory row describing a registered edge.
// PublicKey is an opaque string supplied by the installer for out-of-band
// identity attestation; the hub does not cryptographically bind it to the
// cert — the node_id + cert serial pair is the auth-level identity.
type NodeRecord struct {
	ID              string    `json:"id"`
	Type            string    `json:"type"`
	PublicKey       string    `json:"public_key,omitempty"`
	CertSerial      string    `json:"cert_serial"`
	AssignedTenants []string  `json:"assigned_tenants,omitempty"`
	RegisteredAt    time.Time `json:"registered_at"`
	LastSeen        time.Time `json:"last_seen"`
}

// NodeStore is the in-memory edge-node registry. A future wave will mirror
// it to disk alongside the tenant files; the API surface is designed so that
// change is transparent to callers.
type NodeStore struct {
	mu    sync.RWMutex
	nodes map[string]NodeRecord // keyed by node ID
}

// NewNodeStore returns an empty NodeStore.
func NewNodeStore() *NodeStore {
	return &NodeStore{nodes: make(map[string]NodeRecord)}
}

// RegisterRequest is the wire payload posted to /v1/nodes/register.
type RegisterRequest struct {
	NodeID    string `json:"node_id"`
	NodeType  string `json:"node_type"`
	CSRPEM    string `json:"csr_pem"`
	PublicKey string `json:"public_key,omitempty"`
}

// RegisterResponse is what the hub returns on a successful registration.
type RegisterResponse struct {
	CertPEM string `json:"cert_pem"`
	CAPEM   string `json:"ca_pem"`
	Serial  string `json:"serial"`
}

// Register validates the CSR, asks the CA to sign it, and stores a
// NodeRecord keyed on node_id. If the ID is already present the call
// replaces the record — installer retries after a partial failure must
// yield a fresh cert, which is what operators expect.
//
// Returns the signed cert PEM, the CA PEM (so the installer can pin the
// server), and the assigned serial as a decimal string.
func (ns *NodeStore) Register(req RegisterRequest, ca *CA) (RegisterResponse, error) {
	if req.NodeID == "" {
		return RegisterResponse{}, errors.New("hub/nodes: node_id is required")
	}
	if req.NodeType == "" {
		return RegisterResponse{}, errors.New("hub/nodes: node_type is required")
	}
	if req.CSRPEM == "" {
		return RegisterResponse{}, errors.New("hub/nodes: csr_pem is required")
	}
	if ca == nil {
		return RegisterResponse{}, errors.New("hub/nodes: CA not configured")
	}

	der, serial, err := ca.SignCSR([]byte(req.CSRPEM), req.NodeID, req.NodeType, nodeCertValidity)
	if err != nil {
		return RegisterResponse{}, fmt.Errorf("hub/nodes: sign csr: %w", err)
	}

	certPEM := pemEncode("CERTIFICATE", der)
	caPEM := pemEncode("CERTIFICATE", ca.RootCert().Raw)

	rec := NodeRecord{
		ID:           req.NodeID,
		Type:         req.NodeType,
		PublicKey:    req.PublicKey,
		CertSerial:   serial.String(),
		RegisteredAt: time.Now().UTC(),
		LastSeen:     time.Now().UTC(),
	}
	ns.mu.Lock()
	ns.nodes[req.NodeID] = rec
	ns.mu.Unlock()

	return RegisterResponse{
		CertPEM: certPEM,
		CAPEM:   caPEM,
		Serial:  serial.String(),
	}, nil
}

// Get returns a node by ID and whether it exists.
func (ns *NodeStore) Get(id string) (NodeRecord, bool) {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	rec, ok := ns.nodes[id]
	return rec, ok
}

// GetBySerial scans for a node whose cert serial matches. Used by the
// mTLS middleware which only has the peer cert's serial at hand.
func (ns *NodeStore) GetBySerial(serial string) (NodeRecord, bool) {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	for _, rec := range ns.nodes {
		if rec.CertSerial == serial {
			return rec, true
		}
	}
	return NodeRecord{}, false
}

// List returns every registered node, sorted by ID for stable output.
func (ns *NodeStore) List() []NodeRecord {
	ns.mu.RLock()
	out := make([]NodeRecord, 0, len(ns.nodes))
	for _, rec := range ns.nodes {
		out = append(out, rec)
	}
	ns.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Delete revokes the node's cert in the CA (if still present in the store)
// and removes the record. Missing nodes are not an error.
func (ns *NodeStore) Delete(id string, ca *CA) error {
	ns.mu.Lock()
	rec, ok := ns.nodes[id]
	if ok {
		delete(ns.nodes, id)
	}
	ns.mu.Unlock()

	if !ok {
		return nil
	}
	if ca != nil && rec.CertSerial != "" {
		serial, ok := new(big.Int).SetString(rec.CertSerial, 10)
		if ok {
			if err := ca.Revoke(serial); err != nil {
				return fmt.Errorf("hub/nodes: revoke %s: %w", id, err)
			}
		}
	}
	return nil
}

// SetAssignedTenants replaces the tenant assignment list for a node. An
// unknown ID is an error — callers never want to silently create a record
// this way (that path is Register).
func (ns *NodeStore) SetAssignedTenants(id string, hosts []string) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	rec, ok := ns.nodes[id]
	if !ok {
		return fmt.Errorf("hub/nodes: unknown node %q", id)
	}
	cp := make([]string, len(hosts))
	copy(cp, hosts)
	rec.AssignedTenants = cp
	ns.nodes[id] = rec
	return nil
}

// Touch updates LastSeen for a node. Unknown IDs are ignored (a peer cert
// may be valid but the node record could have been trimmed out of band).
func (ns *NodeStore) Touch(id string) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	rec, ok := ns.nodes[id]
	if !ok {
		return
	}
	rec.LastSeen = time.Now().UTC()
	ns.nodes[id] = rec
}

// TenantAllowed reports whether the node with id may see events for a
// given tenant host. An empty AssignedTenants list means "all tenants" —
// matching the default behaviour described in the spec ("*" = all proxies).
func (ns *NodeStore) TenantAllowed(id, host string) bool {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	rec, ok := ns.nodes[id]
	if !ok {
		// Unknown caller: deny. This is the safe default; callers that
		// want an unregistered edge to see tenants must Register first.
		return false
	}
	if len(rec.AssignedTenants) == 0 {
		return true
	}
	for _, h := range rec.AssignedTenants {
		if h == "*" || h == host {
			return true
		}
	}
	return false
}

// AsNodeInfos returns the list shaped for the shared.NodeInfo wire type.
// Callers that want the internal representation use List.
func (ns *NodeStore) AsNodeInfos() []shared.NodeInfo {
	recs := ns.List()
	out := make([]shared.NodeInfo, 0, len(recs))
	for _, r := range recs {
		out = append(out, shared.NodeInfo{
			ID:              r.ID,
			Type:            r.Type,
			PublicKey:       r.PublicKey,
			AssignedTenants: append([]string(nil), r.AssignedTenants...),
			CertSerial:      r.CertSerial,
			RegisteredAt:    r.RegisteredAt,
			LastSeen:        r.LastSeen,
		})
	}
	return out
}

// marshalJSON is a tiny helper used by tests and debug output.
func (ns *NodeStore) marshalJSON() ([]byte, error) {
	return json.Marshal(ns.List())
}

// pemEncode wraps DER bytes in a PEM block.
func pemEncode(blockType string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}
