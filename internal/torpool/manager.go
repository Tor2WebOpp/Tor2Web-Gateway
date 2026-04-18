package torpool

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

// ErrShuttingDown is returned by mutation operations after Shutdown has
// been initiated. Callers (notably the /scale API handler) map this to
// a 503 response.
var ErrShuttingDown = errors.New("torpool: manager is shutting down")

// waitInstanceExit blocks up to timeout waiting for inst.exited to close,
// so the OS has a chance to release the SOCKS listen port before we
// attempt to rebind. Only the per-instance Wait goroutine in spawnInstance
// is allowed to call cmd.Wait; callers who need to block use this helper.
// Returns true if the process exited within the timeout, false otherwise.
func waitInstanceExit(inst *TorInstance, timeout time.Duration) bool {
	if inst == nil || inst.exited == nil {
		return true
	}
	select {
	case <-inst.exited:
		return true
	case <-time.After(timeout):
		return false
	}
}

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

	// cmd is retained for diagnostics. The underlying cmd.Wait is invoked
	// exactly once by the background goroutine spawned in spawnInstance;
	// callers that need to block until the process reaps should select on
	// exited instead of calling Wait directly (double-Wait is a data race).
	cmd *exec.Cmd

	// exited is closed by the single background Wait goroutine once the
	// OS has reaped the process. killAndWait blocks on this channel
	// (bounded by a timeout) to know the SOCKS port is free.
	exited chan struct{}
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
	// opMu serialises mutation operations (ScaleTo, ReplaceInstance,
	// spawn/add/remove). mu is still held for the short read/write of
	// the instances slice on hot paths; opMu is held around the larger
	// kill+wait+spawn sequence to keep concurrent /scale and healthcheck
	// replace from double-killing or racing spawn-on-bound-port.
	opMu         sync.Mutex
	shuttingDown atomic.Bool
	startTime    time.Time
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
// and waits for "Bootstrapped 100%" on either stdout or stderr. On bootstrap
// timeout it cancels the context, kills the process, and waits up to 5s for
// the OS to release the SOCKS port before returning — otherwise the zombie
// tor holds the port and the next respawn fails with "address already in use".
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
		exited:  make(chan struct{}),
	}

	cmd := exec.CommandContext(instCtx, torBin, "-f", torrcPath)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		close(inst.exited)
		return fmt.Errorf("stdout pipe: %w", err)
	}
	// Route stderr through slog instead of os.Stderr — tor's torrc has
	// "Log notice stderr" so the bootstrap log and all steady-state
	// events arrive here. We also scan for "Bootstrapped 100%" on this
	// stream because tor logs bootstrap progress to stderr, not stdout.
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		close(inst.exited)
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		close(inst.exited)
		return fmt.Errorf("start tor process: %w", err)
	}

	inst.Process = cmd.Process
	inst.cmd = cmd

	// Start the single cmd.Wait goroutine up front. Any callers needing to
	// block on process exit must use waitInstanceExit, not call Wait
	// themselves — multiple goroutines calling Wait on the same cmd is a
	// data race per os/exec docs.
	go func() {
		cmd.Wait() //nolint:errcheck
		inst.Alive.Store(false)
		close(inst.exited)
	}()

	// Monitor both stdout and stderr for bootstrap completion. Fire the
	// bootstrapped channel on the first match from either stream; keep
	// reading after to drain the pipes and forward stderr to slog.
	bootstrapped := make(chan struct{}, 1)
	signalBootstrapped := func() {
		select {
		case bootstrapped <- struct{}{}:
		default:
		}
	}
	scanPipe := func(r io.Reader, stream string) {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Bootstrapped 100%") {
				signalBootstrapped()
			}
			if stream == "stderr" {
				slog.Info("tor.stderr", "port", port, "line", line)
			}
		}
	}
	go scanPipe(stdoutPipe, "stdout")
	go scanPipe(stderrPipe, "stderr")

	// Wait for bootstrap or timeout.
	bootstrapTimer := time.NewTimer(timeout)
	defer bootstrapTimer.Stop()

	select {
	case <-bootstrapped:
		inst.Alive.Store(true)
	case <-bootstrapTimer.C:
		// Bootstrap timeout: do NOT leave a zombie holding the SOCKS port.
		// 1) cancel the context so exec.CommandContext starts teardown
		// 2) send Kill synchronously in case the OS is slow to react
		// 3) block on inst.exited (the single Wait goroutine) for up to 5s
		inst.Alive.Store(false)
		cancel()
		if inst.Process != nil {
			inst.Process.Kill() //nolint:errcheck
		}
		if !waitInstanceExit(inst, 5*time.Second) {
			slog.Warn("torpool: tor process did not exit within 5s after bootstrap timeout",
				"port", port)
		}
		return fmt.Errorf("tor bootstrap timeout after %s on port %d", timeout, port)
	case <-ctx.Done():
		cancel()
		if inst.Process != nil {
			inst.Process.Kill() //nolint:errcheck
		}
		waitInstanceExit(inst, 5*time.Second)
		return ctx.Err()
	}

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

// doMutation serialises mutation operations (ScaleTo, ReplaceInstance)
// behind opMu so healthcheck-triggered replaces and operator-triggered
// scale requests cannot double-kill the same instance or race on a
// freshly-unbound SOCKS port.
func (m *Manager) doMutation(ctx context.Context, fn func() error) error {
	if m.shuttingDown.Load() {
		return ErrShuttingDown
	}
	m.opMu.Lock()
	defer m.opMu.Unlock()
	if m.shuttingDown.Load() {
		return ErrShuttingDown
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fn()
}

// killAndWait cancels, kills, and waits (up to 5s) for a Tor process
// to release its OS resources — most importantly its SOCKS port. Returns
// true if the process exited cleanly within the timeout. Safe against a
// nil Process/cmd (the ReplaceInstance-after-failed-spawn path).
func killAndWait(inst *TorInstance) bool {
	if inst == nil {
		return true
	}
	inst.Alive.Store(false)
	if inst.Cancel != nil {
		inst.Cancel()
	}
	if inst.Process != nil {
		inst.Process.Kill() //nolint:errcheck
	}
	return waitInstanceExit(inst, 5*time.Second)
}

// ScaleTo adjusts the number of instances to the target, clamped to [min, max].
func (m *Manager) ScaleTo(ctx context.Context, target int) error {
	return m.doMutation(ctx, func() error {
		return m.scaleToLocked(ctx, target)
	})
}

// scaleToLocked is the body of ScaleTo, callable only with opMu held.
func (m *Manager) scaleToLocked(ctx context.Context, target int) error {
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
		// Sort ascending: best (lowest Score) first, worst (dead → MaxFloat64) last.
		// Then keep [:target] and kill the tail, so dead instances die first and
		// alive ones survive.
		sort.Slice(m.instances, func(i, j int) bool {
			return m.instances[i].Info().Score() < m.instances[j].Info().Score()
		})
		toKill := make([]*TorInstance, len(m.instances[target:]))
		copy(toKill, m.instances[target:])
		m.instances = m.instances[:target]
		m.mu.Unlock()

		// Wait after each kill so SOCKS ports are released before the caller
		// (or the next ScaleTo) tries to rebind.
		for _, inst := range toKill {
			killAndWait(inst)
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

// ReplaceInstance kills the instance on the given port and spawns a replacement
// on the same port+backend. It blocks on the dead process's Wait before
// respawning so the SOCKS port is free when the new tor attempts to bind.
func (m *Manager) ReplaceInstance(ctx context.Context, port int) error {
	return m.doMutation(ctx, func() error {
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

		// Kill the dead instance, then block on Wait so the OS releases the
		// SOCKS port before we attempt to respawn on it.
		killAndWait(dead)

		// Spawn a replacement on the now-free port.
		return m.spawnInstance(ctx, port, dead.Backend)
	})
}

// Shutdown cancels all running instances. Sets the shuttingDown flag so
// subsequent ScaleTo / ReplaceInstance calls fail fast with ErrShuttingDown.
func (m *Manager) Shutdown() {
	m.shuttingDown.Store(true)
	// Best-effort cooperation with doMutation — acquire opMu so we drain any
	// in-flight mutation. Callers of Shutdown expect synchronous teardown.
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, inst := range m.instances {
		inst.Alive.Store(false)
		if inst.Cancel != nil {
			inst.Cancel()
		}
		if inst.Process != nil {
			inst.Process.Kill() //nolint:errcheck
		}
	}
}

// IsShuttingDown reports whether Shutdown has been called. Used by the
// API handler to return 503 on /scale after shutdown has started.
func (m *Manager) IsShuttingDown() bool {
	return m.shuttingDown.Load()
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
