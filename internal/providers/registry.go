// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package providers

import (
	"fmt"
	"sync"

	"github.com/zero-day-ai/gibson-framework/internal/model"
)

// Registry manages provider URL resolution with thread-safe caching
type Registry struct {
	adapter   *ProviderAdapter
	cache     map[string]string
	cacheMux  sync.RWMutex
}

// NewRegistry creates a new provider registry
func NewRegistry() *Registry {
	return &Registry{
		adapter: NewProviderAdapter(),
		cache:   make(map[string]string),
	}
}

// ResolveURL resolves the URL for a provider with caching
// Returns the resolved URL or an error if resolution fails
func (r *Registry) ResolveURL(provider model.Provider, userURL string) (string, error) {
	// If user provided URL, return it directly (no caching needed)
	if userURL != "" {
		return userURL, nil
	}

	// Create cache key
	cacheKey := string(provider)

	// Check cache first (read lock)
	r.cacheMux.RLock()
	if cachedURL, exists := r.cache[cacheKey]; exists {
		r.cacheMux.RUnlock()
		return cachedURL, nil
	}
	r.cacheMux.RUnlock()

	// Resolve URL through adapter
	resolvedURL, err := r.adapter.ResolveURL(provider, userURL)
	if err != nil {
		return "", err
	}

	// Cache the result (write lock)
	r.cacheMux.Lock()
	r.cache[cacheKey] = resolvedURL
	r.cacheMux.Unlock()

	return resolvedURL, nil
}

// ValidateModel validates a model name for a provider
// Returns an error if validation fails (can be treated as warning)
func (r *Registry) ValidateModel(provider model.Provider, modelName string) error {
	return r.adapter.ValidateLangChainModel(provider, modelName)
}

// GetSupportedProviders returns a list of all supported providers
func (r *Registry) GetSupportedProviders() []model.Provider {
	return []model.Provider{
		model.ProviderAnthropic,
		model.ProviderOpenAI,
		model.ProviderGoogle,
		model.ProviderCohere,
		model.ProviderHuggingFace,
		model.ProviderAzure,
		model.ProviderCustom,
		model.ProviderOllama,
	}
}

// IsKnownProvider returns true if the provider is supported
func (r *Registry) IsKnownProvider(provider model.Provider) bool {
	return r.adapter.IsKnownProvider(provider)
}

// GetDefaultURL returns the default URL for a provider (if available)
func (r *Registry) GetDefaultURL(provider model.Provider) (string, bool) {
	return r.adapter.GetDefaultURL(provider)
}

// ClearCache clears the URL resolution cache
func (r *Registry) ClearCache() {
	r.cacheMux.Lock()
	defer r.cacheMux.Unlock()
	r.cache = make(map[string]string)
}

// GetCacheSize returns the number of cached URL resolutions
func (r *Registry) GetCacheSize() int {
	r.cacheMux.RLock()
	defer r.cacheMux.RUnlock()
	return len(r.cache)
}

// GetSupportedProvidersString returns a formatted string of supported providers
func (r *Registry) GetSupportedProvidersString() string {
	providers := r.GetSupportedProviders()
	var result string
	for i, provider := range providers {
		if i > 0 {
			result += ", "
		}
		result += string(provider)
	}
	return result
}

// CreateProviderError creates a descriptive error message for unsupported providers
func (r *Registry) CreateProviderError(provider model.Provider) error {
	if r.IsKnownProvider(provider) {
		return fmt.Errorf("provider '%s' requires a custom URL (use --url flag)", provider)
	}

	supportedProviders := r.GetSupportedProvidersString()
	return fmt.Errorf("unsupported provider '%s'. Supported providers: %s", provider, supportedProviders)
}