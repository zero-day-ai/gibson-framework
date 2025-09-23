// Package validation provides rate limiting for security and DoS prevention
package validation

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// RateLimit represents a rate limit configuration
type RateLimit struct {
	Requests int           `json:"requests"`
	Window   time.Duration `json:"window"`
}

// RateLimiter provides rate limiting functionality
type RateLimiter struct {
	limits map[string]*RateLimit
	store  map[string]*rateLimitEntry
	mutex  sync.RWMutex
}

// rateLimitEntry represents a rate limit entry for a specific key
type rateLimitEntry struct {
	count     int
	resetTime time.Time
	mutex     sync.Mutex
}

// RateLimitResult represents the result of a rate limit check
type RateLimitResult struct {
	Allowed     bool          `json:"allowed"`
	Remaining   int           `json:"remaining"`
	ResetTime   time.Time     `json:"reset_time"`
	RetryAfter  time.Duration `json:"retry_after,omitempty"`
	LimitType   string        `json:"limit_type"`
}

// NewRateLimiter creates a new rate limiter with default limits
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		limits: make(map[string]*RateLimit),
		store:  make(map[string]*rateLimitEntry),
	}

	// Set default rate limits for Gibson security operations
	rl.SetLimit("validation_requests", &RateLimit{
		Requests: 1000,
		Window:   time.Minute,
	})

	rl.SetLimit("credential_operations", &RateLimit{
		Requests: 100,
		Window:   time.Minute,
	})

	rl.SetLimit("target_operations", &RateLimit{
		Requests: 200,
		Window:   time.Minute,
	})

	rl.SetLimit("scan_operations", &RateLimit{
		Requests: 50,
		Window:   time.Minute,
	})

	rl.SetLimit("payload_operations", &RateLimit{
		Requests: 500,
		Window:   time.Minute,
	})

	rl.SetLimit("report_generation", &RateLimit{
		Requests: 10,
		Window:   time.Minute,
	})

	rl.SetLimit("authentication_attempts", &RateLimit{
		Requests: 5,
		Window:   time.Minute,
	})

	rl.SetLimit("api_requests_per_ip", &RateLimit{
		Requests: 1000,
		Window:   time.Hour,
	})

	rl.SetLimit("api_requests_per_user", &RateLimit{
		Requests: 5000,
		Window:   time.Hour,
	})

	// Start cleanup routine
	go rl.cleanupRoutine()

	return rl
}

// SetLimit sets or updates a rate limit
func (rl *RateLimiter) SetLimit(limitType string, limit *RateLimit) {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()
	rl.limits[limitType] = limit
}

// GetLimit retrieves a rate limit configuration
func (rl *RateLimiter) GetLimit(limitType string) (*RateLimit, bool) {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()
	limit, exists := rl.limits[limitType]
	return limit, exists
}

// Check checks if a request is allowed under the rate limit
func (rl *RateLimiter) Check(limitType, key string) *RateLimitResult {
	rl.mutex.RLock()
	limit, exists := rl.limits[limitType]
	rl.mutex.RUnlock()

	if !exists {
		return &RateLimitResult{
			Allowed:   true,
			Remaining: -1,
			LimitType: limitType,
		}
	}

	entryKey := fmt.Sprintf("%s:%s", limitType, key)

	rl.mutex.Lock()
	entry, exists := rl.store[entryKey]
	if !exists {
		entry = &rateLimitEntry{
			count:     0,
			resetTime: time.Now().Add(limit.Window),
		}
		rl.store[entryKey] = entry
	}
	rl.mutex.Unlock()

	entry.mutex.Lock()
	defer entry.mutex.Unlock()

	now := time.Now()

	// Reset if window has passed
	if now.After(entry.resetTime) {
		entry.count = 0
		entry.resetTime = now.Add(limit.Window)
	}

	// Check if limit exceeded
	if entry.count >= limit.Requests {
		return &RateLimitResult{
			Allowed:    false,
			Remaining:  0,
			ResetTime:  entry.resetTime,
			RetryAfter: time.Until(entry.resetTime),
			LimitType:  limitType,
		}
	}

	// Increment counter and allow request
	entry.count++

	return &RateLimitResult{
		Allowed:   true,
		Remaining: limit.Requests - entry.count,
		ResetTime: entry.resetTime,
		LimitType: limitType,
	}
}

// Allow is a convenience method that checks and returns boolean
func (rl *RateLimiter) Allow(limitType, key string) bool {
	result := rl.Check(limitType, key)
	return result.Allowed
}

// Reset resets the rate limit for a specific key
func (rl *RateLimiter) Reset(limitType, key string) {
	entryKey := fmt.Sprintf("%s:%s", limitType, key)

	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	if entry, exists := rl.store[entryKey]; exists {
		entry.mutex.Lock()
		entry.count = 0
		entry.resetTime = time.Now().Add(rl.limits[limitType].Window)
		entry.mutex.Unlock()
	}
}

// GetStats returns statistics about rate limit usage
func (rl *RateLimiter) GetStats() map[string]interface{} {
	rl.mutex.RLock()
	defer rl.mutex.RUnlock()

	stats := map[string]interface{}{
		"total_entries":     len(rl.store),
		"configured_limits": len(rl.limits),
		"limits":           rl.limits,
	}

	// Count entries per limit type
	limitCounts := make(map[string]int)
	for key := range rl.store {
		if colonIndex := strings.Index(key, ":"); colonIndex > 0 {
			limitType := key[:colonIndex]
			limitCounts[limitType]++
		}
	}
	stats["entries_per_limit"] = limitCounts

	return stats
}

// cleanupRoutine periodically removes expired entries
func (rl *RateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.cleanup()
	}
}

// cleanup removes expired rate limit entries
func (rl *RateLimiter) cleanup() {
	rl.mutex.Lock()
	defer rl.mutex.Unlock()

	now := time.Now()
	var toDelete []string

	for key, entry := range rl.store {
		entry.mutex.Lock()
		if now.After(entry.resetTime.Add(time.Minute)) { // Add buffer time
			toDelete = append(toDelete, key)
		}
		entry.mutex.Unlock()
	}

	for _, key := range toDelete {
		delete(rl.store, key)
	}
}

// ValidationRateLimiter provides rate limiting specifically for validation operations
type ValidationRateLimiter struct {
	rateLimiter *RateLimiter
}

// NewValidationRateLimiter creates a rate limiter for validation operations
func NewValidationRateLimiter() *ValidationRateLimiter {
	return &ValidationRateLimiter{
		rateLimiter: NewRateLimiter(),
	}
}

// CheckValidationRequest checks if a validation request is allowed
func (vrl *ValidationRateLimiter) CheckValidationRequest(clientIP, userID string) *RateLimitResult {
	// Check IP-based rate limit first (more restrictive)
	ipResult := vrl.rateLimiter.Check("api_requests_per_ip", clientIP)
	if !ipResult.Allowed {
		return ipResult
	}

	// Check user-based rate limit if user is identified
	if userID != "" {
		userResult := vrl.rateLimiter.Check("api_requests_per_user", userID)
		if !userResult.Allowed {
			return userResult
		}
	}

	// Check general validation rate limit
	return vrl.rateLimiter.Check("validation_requests", clientIP)
}

// CheckCredentialOperation checks if a credential operation is allowed
func (vrl *ValidationRateLimiter) CheckCredentialOperation(clientIP, userID string) *RateLimitResult {
	key := clientIP
	if userID != "" {
		key = userID
	}
	return vrl.rateLimiter.Check("credential_operations", key)
}

// CheckTargetOperation checks if a target operation is allowed
func (vrl *ValidationRateLimiter) CheckTargetOperation(clientIP, userID string) *RateLimitResult {
	key := clientIP
	if userID != "" {
		key = userID
	}
	return vrl.rateLimiter.Check("target_operations", key)
}

// CheckScanOperation checks if a scan operation is allowed
func (vrl *ValidationRateLimiter) CheckScanOperation(clientIP, userID string) *RateLimitResult {
	key := clientIP
	if userID != "" {
		key = userID
	}
	return vrl.rateLimiter.Check("scan_operations", key)
}

// CheckPayloadOperation checks if a payload operation is allowed
func (vrl *ValidationRateLimiter) CheckPayloadOperation(clientIP, userID string) *RateLimitResult {
	key := clientIP
	if userID != "" {
		key = userID
	}
	return vrl.rateLimiter.Check("payload_operations", key)
}

// CheckReportGeneration checks if a report generation is allowed
func (vrl *ValidationRateLimiter) CheckReportGeneration(clientIP, userID string) *RateLimitResult {
	key := clientIP
	if userID != "" {
		key = userID
	}
	return vrl.rateLimiter.Check("report_generation", key)
}

// CheckAuthenticationAttempt checks if an authentication attempt is allowed
func (vrl *ValidationRateLimiter) CheckAuthenticationAttempt(clientIP string) *RateLimitResult {
	return vrl.rateLimiter.Check("authentication_attempts", clientIP)
}

// BurstRateLimiter provides burst protection for high-frequency operations
type BurstRateLimiter struct {
	tokens     int
	maxTokens  int
	refillRate time.Duration
	lastRefill time.Time
	mutex      sync.Mutex
}

// NewBurstRateLimiter creates a token bucket rate limiter
func NewBurstRateLimiter(maxTokens int, refillRate time.Duration) *BurstRateLimiter {
	return &BurstRateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request can be processed (consumes a token)
func (brl *BurstRateLimiter) Allow() bool {
	brl.mutex.Lock()
	defer brl.mutex.Unlock()

	now := time.Now()
	elapsed := now.Sub(brl.lastRefill)

	// Refill tokens based on elapsed time
	tokensToAdd := int(elapsed / brl.refillRate)
	if tokensToAdd > 0 {
		brl.tokens = min(brl.maxTokens, brl.tokens+tokensToAdd)
		brl.lastRefill = now
	}

	if brl.tokens > 0 {
		brl.tokens--
		return true
	}

	return false
}

// GetTokens returns the current number of available tokens
func (brl *BurstRateLimiter) GetTokens() int {
	brl.mutex.Lock()
	defer brl.mutex.Unlock()
	return brl.tokens
}

// AdaptiveRateLimiter adjusts rate limits based on system load
type AdaptiveRateLimiter struct {
	baseLimiter     *RateLimiter
	loadThresholds  map[string]float64
	currentLoad     float64
	adaptationRate  float64
	mutex          sync.RWMutex
}

// NewAdaptiveRateLimiter creates an adaptive rate limiter
func NewAdaptiveRateLimiter() *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		baseLimiter: NewRateLimiter(),
		loadThresholds: map[string]float64{
			"low":    0.3,
			"medium": 0.7,
			"high":   0.9,
		},
		currentLoad:    0.0,
		adaptationRate: 0.5,
	}
}

// UpdateLoad updates the current system load (0.0 to 1.0)
func (arl *AdaptiveRateLimiter) UpdateLoad(load float64) {
	arl.mutex.Lock()
	defer arl.mutex.Unlock()

	// Smooth load changes
	arl.currentLoad = arl.currentLoad*(1-arl.adaptationRate) + load*arl.adaptationRate
}

// Check performs adaptive rate limit checking
func (arl *AdaptiveRateLimiter) Check(limitType, key string) *RateLimitResult {
	arl.mutex.RLock()
	currentLoad := arl.currentLoad
	arl.mutex.RUnlock()

	// Get base result
	result := arl.baseLimiter.Check(limitType, key)

	if !result.Allowed {
		return result
	}

	// Apply adaptive logic
	adaptiveFactor := arl.calculateAdaptiveFactor(currentLoad)

	// Reduce remaining count based on load
	if adaptiveFactor < 1.0 {
		adjustedRemaining := int(float64(result.Remaining) * adaptiveFactor)
		if adjustedRemaining < result.Remaining {
			result.Remaining = adjustedRemaining
		}

		// Under high load, probabilistically deny some requests
		if currentLoad > arl.loadThresholds["high"] {
			denyProbability := (currentLoad - arl.loadThresholds["high"]) / (1.0 - arl.loadThresholds["high"])
			if time.Now().UnixNano()%100 < int64(denyProbability*100) {
				result.Allowed = false
				result.Remaining = 0
			}
		}
	}

	return result
}

// calculateAdaptiveFactor returns a factor (0.0 to 1.0) to adjust rate limits
func (arl *AdaptiveRateLimiter) calculateAdaptiveFactor(load float64) float64 {
	switch {
	case load < arl.loadThresholds["low"]:
		return 1.0 // No adjustment under low load
	case load < arl.loadThresholds["medium"]:
		// Linear decrease from 1.0 to 0.7
		ratio := (load - arl.loadThresholds["low"]) / (arl.loadThresholds["medium"] - arl.loadThresholds["low"])
		return 1.0 - (ratio * 0.3)
	case load < arl.loadThresholds["high"]:
		// Linear decrease from 0.7 to 0.3
		ratio := (load - arl.loadThresholds["medium"]) / (arl.loadThresholds["high"] - arl.loadThresholds["medium"])
		return 0.7 - (ratio * 0.4)
	default:
		// Aggressive reduction under high load
		return 0.1
	}
}

// Helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// RateLimitMiddleware provides HTTP middleware for rate limiting
type RateLimitMiddleware struct {
	limiter *ValidationRateLimiter
}

// NewRateLimitMiddleware creates HTTP middleware for rate limiting
func NewRateLimitMiddleware() *RateLimitMiddleware {
	return &RateLimitMiddleware{
		limiter: NewValidationRateLimiter(),
	}
}

// GetClientIP extracts client IP from request (helper function)
func GetClientIP(headers map[string]string) string {
	// Check common proxy headers
	if ip := headers["X-Forwarded-For"]; ip != "" {
		// Take the first IP in case of multiple
		if strings.Contains(ip, ",") {
			return strings.TrimSpace(strings.Split(ip, ",")[0])
		}
		return ip
	}

	if ip := headers["X-Real-IP"]; ip != "" {
		return ip
	}

	if ip := headers["CF-Connecting-IP"]; ip != "" {
		return ip
	}

	// Fallback to remote address
	if ip := headers["Remote-Addr"]; ip != "" {
		return ip
	}

	return "unknown"
}