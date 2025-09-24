// Package ratelimit provides rate limiting functionality for sensitive operations
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/metrics"
)

var (
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
	ErrInvalidConfig     = errors.New("invalid rate limit configuration")
)

// RateLimiter defines the interface for rate limiters
type RateLimiter interface {
	Allow(ctx context.Context, key string) error
	Reset(key string)
	GetStats(key string) *Stats
}

// Stats represents rate limiting statistics
type Stats struct {
	Key            string    `json:"key"`
	RequestCount   int64     `json:"request_count"`
	AllowedCount   int64     `json:"allowed_count"`
	RejectedCount  int64     `json:"rejected_count"`
	LastRequest    time.Time `json:"last_request"`
	WindowStart    time.Time `json:"window_start"`
	RemainingQuota int64     `json:"remaining_quota"`
	ResetTime      time.Time `json:"reset_time"`
}

// TokenBucketLimiter implements a token bucket rate limiter
type TokenBucketLimiter struct {
	capacity       int64
	refillRate     float64 // tokens per second
	buckets        map[string]*bucket
	mutex          sync.RWMutex
	metricsEnabled bool
}

type bucket struct {
	tokens      float64
	lastRefill  time.Time
	requestCount int64
	allowedCount int64
	rejectedCount int64
	lastRequest time.Time
}

// NewTokenBucketLimiter creates a new token bucket rate limiter
func NewTokenBucketLimiter(capacity int64, refillRate float64) *TokenBucketLimiter {
	if capacity <= 0 || refillRate <= 0 {
		return nil
	}

	return &TokenBucketLimiter{
		capacity:       capacity,
		refillRate:     refillRate,
		buckets:        make(map[string]*bucket),
		metricsEnabled: true,
	}
}

func (tbl *TokenBucketLimiter) Allow(ctx context.Context, key string) error {
	tbl.mutex.Lock()
	defer tbl.mutex.Unlock()

	b, exists := tbl.buckets[key]
	if !exists {
		b = &bucket{
			tokens:     float64(tbl.capacity),
			lastRefill: time.Now(),
		}
		tbl.buckets[key] = b
	}

	now := time.Now()
	b.lastRequest = now
	b.requestCount++

	// Refill tokens
	elapsed := now.Sub(b.lastRefill).Seconds()
	tokensToAdd := elapsed * tbl.refillRate
	b.tokens = min(b.tokens+tokensToAdd, float64(tbl.capacity))
	b.lastRefill = now

	// Check if we can consume a token
	if b.tokens >= 1.0 {
		b.tokens--
		b.allowedCount++

		if tbl.metricsEnabled {
			metrics.GetCounter("rate_limit_allowed_total").Inc()
		}

		return nil
	}

	b.rejectedCount++

	if tbl.metricsEnabled {
		metrics.GetCounter("rate_limit_rejected_total").Inc()
	}

	return ErrRateLimitExceeded
}

func (tbl *TokenBucketLimiter) Reset(key string) {
	tbl.mutex.Lock()
	defer tbl.mutex.Unlock()
	delete(tbl.buckets, key)
}

func (tbl *TokenBucketLimiter) GetStats(key string) *Stats {
	tbl.mutex.RLock()
	defer tbl.mutex.RUnlock()

	b, exists := tbl.buckets[key]
	if !exists {
		return &Stats{Key: key}
	}

	return &Stats{
		Key:            key,
		RequestCount:   b.requestCount,
		AllowedCount:   b.allowedCount,
		RejectedCount:  b.rejectedCount,
		LastRequest:    b.lastRequest,
		WindowStart:    b.lastRefill,
		RemainingQuota: int64(b.tokens),
		ResetTime:      b.lastRefill.Add(time.Duration(float64(tbl.capacity)/tbl.refillRate) * time.Second),
	}
}

// SlidingWindowLimiter implements a sliding window rate limiter
type SlidingWindowLimiter struct {
	limit       int64
	window      time.Duration
	windows     map[string]*slidingWindow
	mutex       sync.RWMutex
	cleanupInterval time.Duration
}

type slidingWindow struct {
	requests      []time.Time
	requestCount  int64
	allowedCount  int64
	rejectedCount int64
	lastRequest   time.Time
}

// NewSlidingWindowLimiter creates a new sliding window rate limiter
func NewSlidingWindowLimiter(limit int64, window time.Duration) *SlidingWindowLimiter {
	if limit <= 0 || window <= 0 {
		return nil
	}

	swl := &SlidingWindowLimiter{
		limit:           limit,
		window:          window,
		windows:         make(map[string]*slidingWindow),
		cleanupInterval: window,
	}

	// Start cleanup goroutine
	go swl.cleanup()

	return swl
}

func (swl *SlidingWindowLimiter) Allow(ctx context.Context, key string) error {
	swl.mutex.Lock()
	defer swl.mutex.Unlock()

	w, exists := swl.windows[key]
	if !exists {
		w = &slidingWindow{
			requests: make([]time.Time, 0),
		}
		swl.windows[key] = w
	}

	now := time.Now()
	w.lastRequest = now
	w.requestCount++

	// Remove old requests outside the window
	cutoff := now.Add(-swl.window)
	validRequests := make([]time.Time, 0)
	for _, reqTime := range w.requests {
		if reqTime.After(cutoff) {
			validRequests = append(validRequests, reqTime)
		}
	}
	w.requests = validRequests

	// Check if we're within the limit
	if int64(len(w.requests)) < swl.limit {
		w.requests = append(w.requests, now)
		w.allowedCount++

		metrics.GetCounter("rate_limit_allowed_total").Inc()

		return nil
	}

	w.rejectedCount++
	metrics.GetCounter("rate_limit_rejected_total").Inc()

	return ErrRateLimitExceeded
}

func (swl *SlidingWindowLimiter) Reset(key string) {
	swl.mutex.Lock()
	defer swl.mutex.Unlock()
	delete(swl.windows, key)
}

func (swl *SlidingWindowLimiter) GetStats(key string) *Stats {
	swl.mutex.RLock()
	defer swl.mutex.RUnlock()

	w, exists := swl.windows[key]
	if !exists {
		return &Stats{Key: key}
	}

	now := time.Now()
	cutoff := now.Add(-swl.window)
	currentRequests := 0
	for _, reqTime := range w.requests {
		if reqTime.After(cutoff) {
			currentRequests++
		}
	}

	return &Stats{
		Key:            key,
		RequestCount:   w.requestCount,
		AllowedCount:   w.allowedCount,
		RejectedCount:  w.rejectedCount,
		LastRequest:    w.lastRequest,
		WindowStart:    cutoff,
		RemainingQuota: swl.limit - int64(currentRequests),
		ResetTime:      now.Add(swl.window),
	}
}

func (swl *SlidingWindowLimiter) cleanup() {
	ticker := time.NewTicker(swl.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		swl.mutex.Lock()
		now := time.Now()
		cutoff := now.Add(-swl.window * 2) // Clean up windows that haven't been used recently

		for key, w := range swl.windows {
			if w.lastRequest.Before(cutoff) {
				delete(swl.windows, key)
			}
		}
		swl.mutex.Unlock()
	}
}

// CompositeLimiter combines multiple rate limiters
type CompositeLimiter struct {
	limiters []RateLimiter
}

// NewCompositeLimiter creates a new composite rate limiter
func NewCompositeLimiter(limiters ...RateLimiter) *CompositeLimiter {
	return &CompositeLimiter{
		limiters: limiters,
	}
}

func (cl *CompositeLimiter) Allow(ctx context.Context, key string) error {
	for _, limiter := range cl.limiters {
		if err := limiter.Allow(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

func (cl *CompositeLimiter) Reset(key string) {
	for _, limiter := range cl.limiters {
		limiter.Reset(key)
	}
}

func (cl *CompositeLimiter) GetStats(key string) *Stats {
	// Return stats from the first limiter
	if len(cl.limiters) > 0 {
		return cl.limiters[0].GetStats(key)
	}
	return &Stats{Key: key}
}

// RateLimitManager manages multiple rate limiters for different operations
type RateLimitManager struct {
	limiters map[string]RateLimiter
	mutex    sync.RWMutex
}

// NewRateLimitManager creates a new rate limit manager
func NewRateLimitManager() *RateLimitManager {
	return &RateLimitManager{
		limiters: make(map[string]RateLimiter),
	}
}

func (rlm *RateLimitManager) RegisterLimiter(operation string, limiter RateLimiter) {
	rlm.mutex.Lock()
	defer rlm.mutex.Unlock()
	rlm.limiters[operation] = limiter
}

func (rlm *RateLimitManager) Allow(ctx context.Context, operation, key string) error {
	rlm.mutex.RLock()
	limiter, exists := rlm.limiters[operation]
	rlm.mutex.RUnlock()

	if !exists {
		// No rate limiter configured for this operation
		return nil
	}

	start := time.Now()
	err := limiter.Allow(ctx, key)
	duration := time.Since(start)

	// Record metrics
	timer := metrics.GetTimer(fmt.Sprintf("rate_limit_check_duration_%s", operation))
	timer.ObserveDuration(duration)

	if err != nil {
		counter := metrics.GetCounter(fmt.Sprintf("rate_limit_exceeded_%s", operation))
		counter.Inc()
	}

	return err
}

func (rlm *RateLimitManager) Reset(operation, key string) {
	rlm.mutex.RLock()
	limiter, exists := rlm.limiters[operation]
	rlm.mutex.RUnlock()

	if exists {
		limiter.Reset(key)
	}
}

func (rlm *RateLimitManager) GetStats(operation, key string) *Stats {
	rlm.mutex.RLock()
	limiter, exists := rlm.limiters[operation]
	rlm.mutex.RUnlock()

	if exists {
		return limiter.GetStats(key)
	}

	return &Stats{Key: key}
}

func (rlm *RateLimitManager) GetAllStats() map[string]map[string]*Stats {
	rlm.mutex.RLock()
	defer rlm.mutex.RUnlock()

	result := make(map[string]map[string]*Stats)

	// This is a simplified implementation
	// In practice, you'd need to track all keys per operation
	for operation := range rlm.limiters {
		result[operation] = make(map[string]*Stats)
	}

	return result
}

// Middleware for rate limiting
func (rlm *RateLimitManager) Middleware(operation string, keyExtractor func(ctx context.Context) string) func(context.Context, func()) error {
	return func(ctx context.Context, next func()) error {
		key := keyExtractor(ctx)
		if err := rlm.Allow(ctx, operation, key); err != nil {
			return err
		}
		next()
		return nil
	}
}

// Predefined rate limiters for common operations
func NewSecurityOperationLimiters() map[string]RateLimiter {
	return map[string]RateLimiter{
		"scan_creation":     NewTokenBucketLimiter(10, 1.0),    // 10 scans per bucket, refill 1/sec
		"payload_execution": NewTokenBucketLimiter(100, 10.0),  // 100 payloads per bucket, refill 10/sec
		"api_calls":         NewSlidingWindowLimiter(1000, time.Minute), // 1000 calls per minute
		"login_attempts":    NewSlidingWindowLimiter(5, 15*time.Minute), // 5 attempts per 15 minutes
		"report_generation": NewTokenBucketLimiter(5, 0.1),     // 5 reports per bucket, refill 1 per 10 sec
	}
}

// Global rate limit manager
var defaultManager = NewRateLimitManager()

func init() {
	// Register default limiters
	for operation, limiter := range NewSecurityOperationLimiters() {
		defaultManager.RegisterLimiter(operation, limiter)
	}
}

// Global convenience functions
func Allow(ctx context.Context, operation, key string) error {
	return defaultManager.Allow(ctx, operation, key)
}

func Reset(operation, key string) {
	defaultManager.Reset(operation, key)
}

func GetStats(operation, key string) *Stats {
	return defaultManager.GetStats(operation, key)
}

func RegisterLimiter(operation string, limiter RateLimiter) {
	defaultManager.RegisterLimiter(operation, limiter)
}

// Helper function
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}