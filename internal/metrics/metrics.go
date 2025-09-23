// Package metrics provides performance monitoring and metrics collection
package metrics

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MetricType represents the type of metric
type MetricType string

const (
	MetricTypeCounter   MetricType = "counter"
	MetricTypeGauge     MetricType = "gauge"
	MetricTypeHistogram MetricType = "histogram"
	MetricTypeTimer     MetricType = "timer"
)

// Metric represents a performance metric
type Metric struct {
	ID          uuid.UUID              `json:"id"`
	Name        string                 `json:"name"`
	Type        MetricType             `json:"type"`
	Value       float64                `json:"value"`
	Unit        string                 `json:"unit"`
	Labels      map[string]string      `json:"labels"`
	Timestamp   time.Time              `json:"timestamp"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// Counter represents a monotonically increasing counter
type Counter struct {
	value float64
	mutex sync.RWMutex
}

// Gauge represents a value that can go up and down
type Gauge struct {
	value float64
	mutex sync.RWMutex
}

// Histogram tracks the distribution of values
type Histogram struct {
	buckets []float64
	counts  []uint64
	sum     float64
	count   uint64
	mutex   sync.RWMutex
}

// Timer tracks timing information
type Timer struct {
	histogram *Histogram
}

// MetricsCollector collects and manages metrics
type MetricsCollector struct {
	counters   map[string]*Counter
	gauges     map[string]*Gauge
	histograms map[string]*Histogram
	timers     map[string]*Timer
	mutex      sync.RWMutex
	startTime  time.Time
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		counters:   make(map[string]*Counter),
		gauges:     make(map[string]*Gauge),
		histograms: make(map[string]*Histogram),
		timers:     make(map[string]*Timer),
		startTime:  time.Now(),
	}
}

// Global metrics collector
var defaultCollector = NewMetricsCollector()

// Counter methods
func (c *Counter) Inc() {
	c.Add(1)
}

func (c *Counter) Add(value float64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.value += value
}

func (c *Counter) Value() float64 {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.value
}

// Gauge methods
func (g *Gauge) Set(value float64) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.value = value
}

func (g *Gauge) Inc() {
	g.Add(1)
}

func (g *Gauge) Dec() {
	g.Add(-1)
}

func (g *Gauge) Add(value float64) {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	g.value += value
}

func (g *Gauge) Value() float64 {
	g.mutex.RLock()
	defer g.mutex.RUnlock()
	return g.value
}

// Histogram methods
func NewHistogram(buckets []float64) *Histogram {
	return &Histogram{
		buckets: buckets,
		counts:  make([]uint64, len(buckets)+1),
	}
}

func (h *Histogram) Observe(value float64) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	h.sum += value
	h.count++

	for i, bucket := range h.buckets {
		if value <= bucket {
			h.counts[i]++
			return
		}
	}
	// Value is greater than all buckets
	h.counts[len(h.buckets)]++
}

func (h *Histogram) Count() uint64 {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.count
}

func (h *Histogram) Sum() float64 {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.sum
}

func (h *Histogram) Buckets() ([]float64, []uint64) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	buckets := make([]float64, len(h.buckets))
	counts := make([]uint64, len(h.counts))
	copy(buckets, h.buckets)
	copy(counts, h.counts)
	return buckets, counts
}

// Timer methods
func NewTimer() *Timer {
	// Default buckets for response times (in seconds)
	buckets := []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	return &Timer{
		histogram: NewHistogram(buckets),
	}
}

func (t *Timer) Time(fn func()) {
	start := time.Now()
	fn()
	t.ObserveDuration(time.Since(start))
}

func (t *Timer) ObserveDuration(duration time.Duration) {
	t.histogram.Observe(duration.Seconds())
}

func (t *Timer) Histogram() *Histogram {
	return t.histogram
}

// MetricsCollector methods
func (mc *MetricsCollector) Counter(name string) *Counter {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if counter, exists := mc.counters[name]; exists {
		return counter
	}

	counter := &Counter{}
	mc.counters[name] = counter
	return counter
}

func (mc *MetricsCollector) Gauge(name string) *Gauge {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if gauge, exists := mc.gauges[name]; exists {
		return gauge
	}

	gauge := &Gauge{}
	mc.gauges[name] = gauge
	return gauge
}

func (mc *MetricsCollector) Histogram(name string, buckets []float64) *Histogram {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if histogram, exists := mc.histograms[name]; exists {
		return histogram
	}

	histogram := NewHistogram(buckets)
	mc.histograms[name] = histogram
	return histogram
}

func (mc *MetricsCollector) Timer(name string) *Timer {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	if timer, exists := mc.timers[name]; exists {
		return timer
	}

	timer := NewTimer()
	mc.timers[name] = timer
	return timer
}

func (mc *MetricsCollector) GetAllMetrics() []Metric {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	var metrics []Metric
	now := time.Now()

	// Collect counters
	for name, counter := range mc.counters {
		metrics = append(metrics, Metric{
			ID:          uuid.New(),
			Name:        name,
			Type:        MetricTypeCounter,
			Value:       counter.Value(),
			Unit:        "count",
			Timestamp:   now,
			Description: "Counter metric",
		})
	}

	// Collect gauges
	for name, gauge := range mc.gauges {
		metrics = append(metrics, Metric{
			ID:          uuid.New(),
			Name:        name,
			Type:        MetricTypeGauge,
			Value:       gauge.Value(),
			Unit:        "value",
			Timestamp:   now,
			Description: "Gauge metric",
		})
	}

	// Collect histograms
	for name, histogram := range mc.histograms {
		metrics = append(metrics, Metric{
			ID:    uuid.New(),
			Name:  name + "_count",
			Type:  MetricTypeHistogram,
			Value: float64(histogram.Count()),
			Unit:  "count",
			Labels: map[string]string{
				"type": "histogram_count",
			},
			Timestamp:   now,
			Description: "Histogram count",
		})

		metrics = append(metrics, Metric{
			ID:    uuid.New(),
			Name:  name + "_sum",
			Type:  MetricTypeHistogram,
			Value: histogram.Sum(),
			Unit:  "total",
			Labels: map[string]string{
				"type": "histogram_sum",
			},
			Timestamp:   now,
			Description: "Histogram sum",
		})
	}

	// Collect timers
	for name, timer := range mc.timers {
		hist := timer.Histogram()
		metrics = append(metrics, Metric{
			ID:    uuid.New(),
			Name:  name + "_duration_seconds",
			Type:  MetricTypeTimer,
			Value: hist.Sum() / float64(hist.Count()),
			Unit:  "seconds",
			Labels: map[string]string{
				"type": "timer_avg",
			},
			Timestamp:   now,
			Description: "Timer average duration",
		})
	}

	return metrics
}

func (mc *MetricsCollector) GetSystemMetrics() []Metric {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	now := time.Now()
	uptime := now.Sub(mc.startTime).Seconds()

	return []Metric{
		{
			ID:          uuid.New(),
			Name:        "system_memory_alloc_bytes",
			Type:        MetricTypeGauge,
			Value:       float64(m.Alloc),
			Unit:        "bytes",
			Timestamp:   now,
			Description: "Bytes of allocated heap objects",
		},
		{
			ID:          uuid.New(),
			Name:        "system_memory_total_alloc_bytes",
			Type:        MetricTypeCounter,
			Value:       float64(m.TotalAlloc),
			Unit:        "bytes",
			Timestamp:   now,
			Description: "Cumulative bytes allocated for heap objects",
		},
		{
			ID:          uuid.New(),
			Name:        "system_memory_sys_bytes",
			Type:        MetricTypeGauge,
			Value:       float64(m.Sys),
			Unit:        "bytes",
			Timestamp:   now,
			Description: "Total bytes of memory obtained from the OS",
		},
		{
			ID:          uuid.New(),
			Name:        "system_gc_count",
			Type:        MetricTypeCounter,
			Value:       float64(m.NumGC),
			Unit:        "count",
			Timestamp:   now,
			Description: "Number of completed GC cycles",
		},
		{
			ID:          uuid.New(),
			Name:        "system_goroutines",
			Type:        MetricTypeGauge,
			Value:       float64(runtime.NumGoroutine()),
			Unit:        "count",
			Timestamp:   now,
			Description: "Number of goroutines",
		},
		{
			ID:          uuid.New(),
			Name:        "system_uptime_seconds",
			Type:        MetricTypeGauge,
			Value:       uptime,
			Unit:        "seconds",
			Timestamp:   now,
			Description: "System uptime in seconds",
		},
	}
}

// Global convenience functions
func GetCounter(name string) *Counter {
	return defaultCollector.Counter(name)
}

func GetGauge(name string) *Gauge {
	return defaultCollector.Gauge(name)
}

func GetHistogram(name string, buckets []float64) *Histogram {
	return defaultCollector.Histogram(name, buckets)
}

func GetTimer(name string) *Timer {
	return defaultCollector.Timer(name)
}

func GetAllMetrics() []Metric {
	return defaultCollector.GetAllMetrics()
}

func GetSystemMetrics() []Metric {
	return defaultCollector.GetSystemMetrics()
}

// Middleware for timing HTTP requests
func TimingMiddleware(name string, next func()) {
	timer := GetTimer(name)
	timer.Time(next)
}

// Middleware for counting operations
func CountingMiddleware(name string, next func()) {
	counter := GetCounter(name)
	counter.Inc()
	next()
}

// Memory monitoring utilities
type MemoryMonitor struct {
	threshold uint64
	callback  func(uint64)
}

func NewMemoryMonitor(thresholdMB uint64, callback func(uint64)) *MemoryMonitor {
	return &MemoryMonitor{
		threshold: thresholdMB * 1024 * 1024, // Convert MB to bytes
		callback:  callback,
	}
}

func (mm *MemoryMonitor) Start(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)

			if m.Alloc > mm.threshold {
				mm.callback(m.Alloc)
			}
		}
	}
}

// Performance profiler
type Profiler struct {
	enabled bool
	samples map[string][]time.Duration
	mutex   sync.RWMutex
}

func NewProfiler() *Profiler {
	return &Profiler{
		enabled: true,
		samples: make(map[string][]time.Duration),
	}
}

func (p *Profiler) Profile(name string, fn func()) {
	if !p.enabled {
		fn()
		return
	}

	start := time.Now()
	fn()
	duration := time.Since(start)

	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.samples[name] = append(p.samples[name], duration)
}

func (p *Profiler) GetStats(name string) (count int, avg, min, max time.Duration) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	samples, exists := p.samples[name]
	if !exists || len(samples) == 0 {
		return 0, 0, 0, 0
	}

	count = len(samples)
	total := time.Duration(0)
	min = samples[0]
	max = samples[0]

	for _, duration := range samples {
		total += duration
		if duration < min {
			min = duration
		}
		if duration > max {
			max = duration
		}
	}

	avg = total / time.Duration(count)
	return count, avg, min, max
}

func (p *Profiler) Reset() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.samples = make(map[string][]time.Duration)
}

func (p *Profiler) Enable() {
	p.enabled = true
}

func (p *Profiler) Disable() {
	p.enabled = false
}

// Global profiler
var defaultProfiler = NewProfiler()

func Profile(name string, fn func()) {
	defaultProfiler.Profile(name, fn)
}

func GetProfileStats(name string) (int, time.Duration, time.Duration, time.Duration) {
	return defaultProfiler.GetStats(name)
}

func ResetProfiler() {
	defaultProfiler.Reset()
}