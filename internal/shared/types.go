package shared

type BackendInfo struct {
	Port        int     `json:"port"`
	Alive       bool    `json:"alive"`
	ActiveConns int     `json:"active_conns"`
	LatencyMs   int     `json:"latency_ms"`
	ErrorRate   float64 `json:"error_rate"`
	Backend     string  `json:"backend"`
}

// Score returns load score. Lower = better = gets more traffic.
// Formula: (active_conns * 2) + (avg_latency_ms / 100) + (error_rate_pct * 10)
func (b BackendInfo) Score() float64 {
	return float64(b.ActiveConns*2) + float64(b.LatencyMs)/100.0 + b.ErrorRate*10.0
}

type PoolHealth struct {
	Instances    int `json:"instances"`
	Alive        int `json:"alive"`
	TotalStreams  int `json:"total_streams"`
	AvgLatencyMs int `json:"avg_latency_ms"`
}

type ScaleRequest struct {
	Target int `json:"target"`
}

type PoolStats struct {
	UptimeSec     int64 `json:"uptime_sec"`
	BytesProxied  int64 `json:"bytes_proxied"`
	CircuitsBuilt int64 `json:"circuits_built"`
}
