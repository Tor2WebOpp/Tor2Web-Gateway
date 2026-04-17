package torpool

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gateway/internal/config"
	"gateway/internal/shared"
)

// TorInstance represents a single running Tor process.
type TorInstance struct {
	Port    int
	Backend string

	Alive      atomic.Bool
	ActiveConns atomic.Int64
	LatencyMs  atomic.Int64
	ErrorCount atomic.Int64
	TotalCount atomic.Int64

	Process *os.Process
	Cancel  context.CancelFunc
	DataDir string
}

// ID returns the unique identifier for this instance.
func (t *TorInstance) ID() string {
	return fmt.Sprintf("tor-%d", t.Port)
}

// Info converts the instance's atomic values to a BackendInfo snapshot.
func (t *TorInstance) Info() shared.BackendInfo {
	total := t.TotalCount.Load()
	errors := t.ErrorCount.Load()

	var errorRate float64
	if total > 0 {
		errorRate = float64(errors) / float64(total)
	}

	return shared.BackendInfo{
		Port:        t.Port,
		Alive:       t.Alive.Load(),
		ActiveConns: int(t.ActiveConns.Load()),
		LatencyMs:   int(t.LatencyMs.Load()),
		ErrorRate:   errorRate,
		Backend:     t.Backend,
	}
}

// Manager manages a pool of Tor process instances.
type Manager struct {
	cfg       *config.Config
	instances []*TorInstance
	mu        sync.RWMutex
	startTime time.Time
}

// NewManager creates a new Manager using the provided config.
func NewManager(cfg *config.Config) *Manager {
	return &Manager{
		cfg:       cfg,
		instances: make([]*TorInstance, 0),
		startTime: time.Now(),
	}
}

// Start verifies the tor binary, creates the data directory, and spawns MinInstances tor processes.
func (m *Manager) Start(ctx context.Context) error {
	torBin := m.cfg.Tor.Binary
	if torBin == "" {
		torBin = "tor"
	}
	if _, err := exec.LookPath(torBin); err != nil {
		return fmt.Errorf("tor binary %q not found in PATH: %w", torBin, err)
	}

	if err := os.MkdirAll(m.cfg.Tor.DataDir, 0700); err != nil {
		return fmt.Errorf("create tor data dir %q: %w", m.cfg.Tor.DataDir, err)
	}

	backends := m.cfg.Backends
	for i := 0; i < m.cfg.Tor.MinInstances; i++ {
		port := m.cfg.Tor.SocksBasePort + i
		backend := ""
		if len(backends) > 0 {
			backend = backends[i%len(backends)].Addr
		}
		if err := m.spawnInstance(ctx, port, backend); err != nil {
			return fmt.Errorf("spawn instance on port %d: %w", port, err)
		}
	}

	return nil
}

// spawnInstance creates a data dir, writes a torrc, starts the tor process,
// and waits for "Bootstrapped 100%" or the bootstrap timeout.
func (m *Manager) spawnInstance(ctx context.Context, port int, backend string) error {
	instanceDir := filepath.Join(m.cfg.Tor.DataDir, fmt.Sprintf("tor-%d", port))
	if err := os.MkdirAll(instanceDir, 0700); err != nil {
		return fmt.Errorf("create instance dir %q: %w", instanceDir, err)
	}

	torrcPath := filepath.Join(instanceDir, "torrc")
	if err := generateTorrc(instanceDir, torrcPath, port); err != nil {
		return fmt.Errorf("generate torrc: %w", err)
	}

	torBin := m.cfg.Tor.Binary
	if torBin == "" {
		torBin = "tor"
	}

	timeout := m.cfg.Tor.BootstrapTimeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	instCtx, cancel := context.WithCancel(ctx)

	inst := &TorInstance{
		Port:    port,
		Backend: backend,
		Cancel:  cancel,
		DataDir: instanceDir,
	}

	cmd := exec.CommandContext(instCtx, torBin, "-f", torrcPath)
	cmd.Stderr = os.Stderr

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start tor process: %w", err)
	}

	inst.Process = cmd.Process

	// Monitor stdout for bootstrap completion.
	bootstrapped := make(chan struct{}, 1)
	go func() {
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Bootstrapped 100%") {
				select {
				case bootstrapped <- struct{}{}:
				default:
				}
			}
		}
		// Drain to avoid blocking
		io.Copy(io.Discard, stdoutPipe) //nolint:errcheck
	}()

	// Wait for bootstrap or timeout.
	bootstrapTimer := time.NewTimer(timeout)
	defer bootstrapTimer.Stop()

	select {
	case <-bootstrapped:
		inst.Alive.Store(true)
	case <-bootstrapTimer.C:
		// Timeout: add instance anyway but mark as not alive.
		inst.Alive.Store(false)
	case <-ctx.Done():
		cancel()
		return ctx.Err()
	}

	// Keep process running in background.
	go func() {
		cmd.Wait() //nolint:errcheck
		inst.Alive.Store(false)
	}()

	m.mu.Lock()
	m.instances = append(m.instances, inst)
	m.mu.Unlock()

	return nil
}

// Instances returns a snapshot of all instances.
func (m *Manager) Instances() []*TorInstance {
	m.mu.RLock()
	defer m.mu.RUnlock()
	snap := make([]*TorInstance, len(m.instances))
	copy(snap, m.instances)
	return snap
}

// AliveInstances returns only the instances currently marked alive.
func (m *Manager) AliveInstances() []*TorInstance {
	m.mu.RLock()
	defer m.mu.RUnlock()
	alive := make([]*TorInstance, 0, len(m.instances))
	for _, inst := range m.instances {
		if inst.Alive.Load() {
			alive = append(alive, inst)
		}
	}
	return alive
}

// Count returns (total, alive) instance counts.
func (m *Manager) Count() (total, alive int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	total = len(m.instances)
	for _, inst := range m.instances {
		if inst.Alive.Load() {
			alive++
		}
	}
	return
}

// ScaleTo adjusts the number of instances to the target, clamped to [min, max].
func (m *Manager) ScaleTo(ctx context.Context, target int) error {
	min := m.cfg.Tor.MinInstances
	max := m.cfg.Tor.MaxInstances
	if target < min {
		target = min
	}
	if max > 0 && target > max {
		target = max
	}

	m.mu.Lock()
	current := len(m.instances)

	if target < current {
		// Scale down -- kill worst-scoring instances.
		sort.Slice(m.instances, func(i, j int) bool {
			return m.instances[i].Info().Score() < m.instances[j].Info().Score()
		})
		// Worst are now at the end; take them out.
		toKill := make([]*TorInstance, len(m.instances[target:]))
		copy(toKill, m.instances[target:])
		m.instances = m.instances[:target]
		m.mu.Unlock()

		for _, inst := range toKill {
			inst.Cancel()
			inst.Alive.Store(false)
			if inst.Process != nil {
				inst.Process.Kill() //nolint:errcheck
			}
		}
		return nil
	}

	if target > current {
		// Scale up -- collect used ports under lock, then spawn outside lock.
		usedPorts := make(map[int]bool, len(m.instances))
		for _, inst := range m.instances {
			usedPorts[inst.Port] = true
		}
		needed := target - current
		m.mu.Unlock()

		backends := m.cfg.Backends
		for i := 0; i < needed; i++ {
			port := m.cfg.Tor.SocksBasePort
			for usedPorts[port] {
				port++
			}
			usedPorts[port] = true

			backend := ""
			if len(backends) > 0 {
				backend = backends[port%len(backends)].Addr
			}
			if err := m.spawnInstance(ctx, port, backend); err != nil {
				return fmt.Errorf("scale up: spawn port %d: %w", port, err)
			}
		}
		return nil
	}

	// target == current, nothing to do.
	m.mu.Unlock()
	return nil
}

// ReplaceInstance kills the instance on the given port and spawns a replacement on the same port+backend.
func (m *Manager) ReplaceInstance(ctx context.Context, port int) error {
	m.mu.Lock()
	var dead *TorInstance
	idx := -1
	for i, inst := range m.instances {
		if inst.Port == port {
			dead = inst
			idx = i
			break
		}
	}
	if dead == nil {
		m.mu.Unlock()
		return fmt.Errorf("no instance on port %d", port)
	}
	// Remove from slice while holding the lock.
	m.instances = append(m.instances[:idx], m.instances[idx+1:]...)
	m.mu.Unlock()

	// Kill the dead instance.
	dead.Cancel()
	dead.Alive.Store(false)
	if dead.Process != nil {
		dead.Process.Kill() //nolint:errcheck
	}

	// Spawn a replacement.
	return m.spawnInstance(ctx, port, dead.Backend)
}

// Shutdown cancels all running instances.
func (m *Manager) Shutdown() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, inst := range m.instances {
		inst.Cancel()
		inst.Alive.Store(false)
		if inst.Process != nil {
			inst.Process.Kill() //nolint:errcheck
		}
	}
}

// UptimeSec returns the number of seconds since the manager was created.
func (m *Manager) UptimeSec() int64 {
	return int64(time.Since(m.startTime).Seconds())
}

// generateTorrc writes a torrc file to torrcPath for the given instanceDir and socksPort.
func generateTorrc(instanceDir, torrcPath string, socksPort int) error {
	content := fmt.Sprintf(`SocksPort 127.0.0.1:%d
DataDirectory %s
Log notice stderr
RunAsDaemon 0
AvoidDiskWrites 1
ExitRelay 0
ExitPolicy reject *:*
CircuitBuildTimeout 30
LearnCircuitBuildTimeout 1
CircuitStreamTimeout 10
MaxCircuitDirtiness 600
NewCircuitPeriod 60
SocksTimeout 60
MaxClientCircuitsPending 256
ConnectionPadding auto
FetchDirInfoEarly 1
`, socksPort, instanceDir)

	return os.WriteFile(torrcPath, []byte(content), 0600)
}
