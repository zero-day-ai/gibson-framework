// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package providers

import (
	"testing"

	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestNewRegistry(t *testing.T) {
	registry := NewRegistry()
	assert.NotNil(t, registry)
	assert.NotNil(t, registry.adapter)
	assert.NotNil(t, registry.cache)
}

func TestRegistryResolveURL(t *testing.T) {
	registry := NewRegistry()

	tests := []struct {
		name        string
		provider    model.Provider
		userURL     string
		expectedURL string
		expectError bool
	}{
		{
			name:        "user URL provided - should use user URL",
			provider:    model.ProviderAnthropic,
			userURL:     "https://custom.api.com",
			expectedURL: "https://custom.api.com",
			expectError: false,
		},
		{
			name:        "anthropic default URL",
			provider:    model.ProviderAnthropic,
			userURL:     "",
			expectedURL: "https://api.anthropic.com/v1/messages",
			expectError: false,
		},
		{
			name:        "openai default URL",
			provider:    model.ProviderOpenAI,
			userURL:     "",
			expectedURL: "https://api.openai.com/v1/chat/completions",
			expectError: false,
		},
		{
			name:        "azure requires URL",
			provider:    model.ProviderAzure,
			userURL:     "",
			expectedURL: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := registry.ResolveURL(tt.provider, tt.userURL)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedURL, url)
			}
		})
	}
}

func TestRegistryResolveURLCaching(t *testing.T) {
	registry := NewRegistry()

	// First call should cache the result
	url1, err1 := registry.ResolveURL(model.ProviderAnthropic, "")
	assert.NoError(t, err1)
	assert.Equal(t, "https://api.anthropic.com/v1/messages", url1)

	// Check cache size
	assert.Equal(t, 1, registry.GetCacheSize())

	// Second call should use cached result
	url2, err2 := registry.ResolveURL(model.ProviderAnthropic, "")
	assert.NoError(t, err2)
	assert.Equal(t, url1, url2)

	// Cache size should still be 1
	assert.Equal(t, 1, registry.GetCacheSize())

	// User URL should not be cached
	url3, err3 := registry.ResolveURL(model.ProviderAnthropic, "https://custom.com")
	assert.NoError(t, err3)
	assert.Equal(t, "https://custom.com", url3)

	// Cache size should still be 1 (user URLs are not cached)
	assert.Equal(t, 1, registry.GetCacheSize())
}

func TestRegistryClearCache(t *testing.T) {
	registry := NewRegistry()

	// Add some entries to cache
	_, _ = registry.ResolveURL(model.ProviderAnthropic, "")
	_, _ = registry.ResolveURL(model.ProviderOpenAI, "")

	assert.Equal(t, 2, registry.GetCacheSize())

	// Clear cache
	registry.ClearCache()
	assert.Equal(t, 0, registry.GetCacheSize())
}

func TestValidateModel(t *testing.T) {
	registry := NewRegistry()

	tests := []struct {
		name        string
		provider    model.Provider
		modelName   string
		expectError bool
	}{
		{
			name:        "valid anthropic model",
			provider:    model.ProviderAnthropic,
			modelName:   "claude-3-opus-20240229",
			expectError: false,
		},
		{
			name:        "invalid anthropic model",
			provider:    model.ProviderAnthropic,
			modelName:   "invalid-model",
			expectError: true,
		},
		{
			name:        "empty model name",
			provider:    model.ProviderAnthropic,
			modelName:   "",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.ValidateModel(tt.provider, tt.modelName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetSupportedProviders(t *testing.T) {
	registry := NewRegistry()
	providers := registry.GetSupportedProviders()

	expectedProviders := []model.Provider{
		model.ProviderAnthropic,
		model.ProviderOpenAI,
		model.ProviderGoogle,
		model.ProviderCohere,
		model.ProviderHuggingFace,
		model.ProviderAzure,
		model.ProviderCustom,
		model.ProviderOllama,
	}

	assert.Len(t, providers, len(expectedProviders))

	for _, expected := range expectedProviders {
		assert.Contains(t, providers, expected)
	}
}

func TestRegistryIsKnownProvider(t *testing.T) {
	registry := NewRegistry()

	knownProviders := []model.Provider{
		model.ProviderAnthropic,
		model.ProviderOpenAI,
		model.ProviderGoogle,
		model.ProviderCohere,
		model.ProviderHuggingFace,
		model.ProviderAzure,
		model.ProviderCustom,
		model.ProviderOllama,
	}

	for _, provider := range knownProviders {
		assert.True(t, registry.IsKnownProvider(provider), "Provider %s should be known", provider)
	}

	unknownProviders := []model.Provider{
		model.Provider("unknown"),
		model.Provider("invalid"),
	}

	for _, provider := range unknownProviders {
		assert.False(t, registry.IsKnownProvider(provider), "Provider %s should be unknown", provider)
	}
}

func TestRegistryGetDefaultURL(t *testing.T) {
	registry := NewRegistry()

	tests := []struct {
		name           string
		provider       model.Provider
		expectedExists bool
		expectedURL    string
	}{
		{
			name:           "anthropic has default",
			provider:       model.ProviderAnthropic,
			expectedExists: true,
			expectedURL:    "https://api.anthropic.com/v1/messages",
		},
		{
			name:           "azure has no default",
			provider:       model.ProviderAzure,
			expectedExists: false,
			expectedURL:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, exists := registry.GetDefaultURL(tt.provider)
			assert.Equal(t, tt.expectedExists, exists)
			if tt.expectedExists {
				assert.Equal(t, tt.expectedURL, url)
			}
		})
	}
}

func TestGetSupportedProvidersString(t *testing.T) {
	registry := NewRegistry()
	providersStr := registry.GetSupportedProvidersString()

	assert.NotEmpty(t, providersStr)
	assert.Contains(t, providersStr, "anthropic")
	assert.Contains(t, providersStr, "openai")
	assert.Contains(t, providersStr, "google")
	assert.Contains(t, providersStr, "cohere")
}

func TestCreateProviderError(t *testing.T) {
	registry := NewRegistry()

	tests := []struct {
		name        string
		provider    model.Provider
		expectError string
	}{
		{
			name:        "azure provider needs URL",
			provider:    model.ProviderAzure,
			expectError: "provider 'azure' requires a custom URL",
		},
		{
			name:        "unknown provider",
			provider:    model.Provider("unknown"),
			expectError: "unsupported provider 'unknown'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.CreateProviderError(tt.provider)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectError)
		})
	}
}