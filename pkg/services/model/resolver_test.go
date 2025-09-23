// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package model

import (
	"context"
	"testing"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewModelResolverService(t *testing.T) {
	tests := []struct {
		name     string
		cacheTTL time.Duration
		expected time.Duration
	}{
		{
			name:     "positive cache TTL",
			cacheTTL: 2 * time.Hour,
			expected: 2 * time.Hour,
		},
		{
			name:     "zero cache TTL defaults to 24 hours",
			cacheTTL: 0,
			expected: 24 * time.Hour,
		},
		{
			name:     "negative cache TTL defaults to 24 hours",
			cacheTTL: -1 * time.Hour,
			expected: 24 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewModelResolverService(tt.cacheTTL)
			require.NotNil(t, service)
			assert.Equal(t, tt.expected, service.cacheTTL)
		})
	}
}

func TestModelResolverService_GetDefaultModel(t *testing.T) {
	ctx := context.Background()
	service := NewModelResolverService(1 * time.Hour)

	tests := []struct {
		name     string
		provider model.Provider
		wantErr  bool
	}{
		{
			name:     "anthropic provider",
			provider: model.ProviderAnthropic,
			wantErr:  false,
		},
		{
			name:     "openai provider",
			provider: model.ProviderOpenAI,
			wantErr:  false,
		},
		{
			name:     "google provider",
			provider: model.ProviderGoogle,
			wantErr:  false,
		},
		{
			name:     "cohere provider",
			provider: model.ProviderCohere,
			wantErr:  false,
		},
		{
			name:     "unsupported provider",
			provider: model.Provider("unsupported"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.GetDefaultModel(ctx, tt.provider)

			if tt.wantErr {
				assert.True(t, result.IsErr())
				assert.NotEmpty(t, result.Error().Error())
			} else {
				assert.True(t, result.IsOk())
				defaultModel := result.Unwrap()
				assert.NotEmpty(t, defaultModel)

				// Verify expected models for known providers
				switch tt.provider {
				case model.ProviderAnthropic:
					assert.Equal(t, "claude-3-5-sonnet-20241022", defaultModel)
				case model.ProviderOpenAI:
					assert.Equal(t, "gpt-4-turbo-preview", defaultModel)
				case model.ProviderGoogle:
					assert.Equal(t, "gemini-1.5-pro", defaultModel)
				case model.ProviderCohere:
					assert.Equal(t, "command-r-plus", defaultModel)
				}
			}
		})
	}
}

func TestModelResolverService_GetAvailableModels(t *testing.T) {
	ctx := context.Background()
	service := NewModelResolverService(1 * time.Hour)

	tests := []struct {
		name         string
		provider     model.Provider
		wantErr      bool
		minModels    int
		hasDefault   bool
	}{
		{
			name:       "anthropic provider",
			provider:   model.ProviderAnthropic,
			wantErr:    false,
			minModels:  2, // Should have at least claude-3-5-sonnet and claude-3-haiku
			hasDefault: true,
		},
		{
			name:       "openai provider",
			provider:   model.ProviderOpenAI,
			wantErr:    false,
			minModels:  2, // Should have at least gpt-4-turbo and gpt-3.5-turbo
			hasDefault: true,
		},
		{
			name:       "google provider",
			provider:   model.ProviderGoogle,
			wantErr:    false,
			minModels:  2, // Should have at least gemini-1.5-pro and gemini-1.0-pro
			hasDefault: true,
		},
		{
			name:       "cohere provider",
			provider:   model.ProviderCohere,
			wantErr:    false,
			minModels:  2, // Should have at least command-r-plus and command
			hasDefault: true,
		},
		{
			name:     "unsupported provider",
			provider: model.Provider("unsupported"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.GetAvailableModels(ctx, tt.provider)

			if tt.wantErr {
				assert.True(t, result.IsErr())
			} else {
				assert.True(t, result.IsOk())
				models := result.Unwrap()
				assert.GreaterOrEqual(t, len(models), tt.minModels)

				// Check if at least one model is marked as default
				if tt.hasDefault {
					hasDefaultModel := false
					for _, m := range models {
						if m.IsDefault {
							hasDefaultModel = true
							break
						}
					}
					assert.True(t, hasDefaultModel, "At least one model should be marked as default")
				}

				// Verify all models have required fields
				for _, m := range models {
					assert.Equal(t, tt.provider, m.Provider)
					assert.NotEmpty(t, m.ModelID)
					assert.NotEmpty(t, m.Family)
					assert.NotEmpty(t, m.Capability)
					assert.Positive(t, m.MaxTokens)
				}
			}
		})
	}
}

func TestModelResolverService_ValidateModel(t *testing.T) {
	ctx := context.Background()
	service := NewModelResolverService(1 * time.Hour)

	tests := []struct {
		name     string
		provider model.Provider
		modelID  string
		wantErr  bool
		expected bool
	}{
		{
			name:     "valid anthropic model",
			provider: model.ProviderAnthropic,
			modelID:  "claude-3-5-sonnet-20241022",
			wantErr:  false,
			expected: true,
		},
		{
			name:     "valid openai model",
			provider: model.ProviderOpenAI,
			modelID:  "gpt-4-turbo-preview",
			wantErr:  false,
			expected: true,
		},
		{
			name:     "invalid model for provider",
			provider: model.ProviderAnthropic,
			modelID:  "nonexistent-model",
			wantErr:  false,
			expected: false,
		},
		{
			name:     "unsupported provider",
			provider: model.Provider("unsupported"),
			modelID:  "any-model",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.ValidateModel(ctx, tt.provider, tt.modelID)

			if tt.wantErr {
				assert.True(t, result.IsErr())
			} else {
				assert.True(t, result.IsOk())
				isValid := result.Unwrap()
				assert.Equal(t, tt.expected, isValid)
			}
		})
	}
}

func TestModelResolverService_Cache(t *testing.T) {
	ctx := context.Background()
	// Use short TTL for testing
	service := NewModelResolverService(100 * time.Millisecond)

	// First call should hit the provider
	result1 := service.GetDefaultModel(ctx, model.ProviderAnthropic)
	assert.True(t, result1.IsOk())
	model1 := result1.Unwrap()

	// Second call should hit cache
	result2 := service.GetDefaultModel(ctx, model.ProviderAnthropic)
	assert.True(t, result2.IsOk())
	model2 := result2.Unwrap()
	assert.Equal(t, model1, model2)

	// Wait for cache to expire
	time.Sleep(150 * time.Millisecond)

	// Third call should hit provider again after cache expiration
	result3 := service.GetDefaultModel(ctx, model.ProviderAnthropic)
	assert.True(t, result3.IsOk())
	model3 := result3.Unwrap()
	assert.Equal(t, model1, model3) // Should still be the same model
}

func TestModelResolverService_ClearCache(t *testing.T) {
	ctx := context.Background()
	service := NewModelResolverService(1 * time.Hour)

	// Populate cache
	result := service.GetDefaultModel(ctx, model.ProviderAnthropic)
	assert.True(t, result.IsOk())

	// Clear cache
	service.ClearCache()

	// Verify cache is cleared by checking internal state
	// Since cache is private, we can't directly verify, but we can ensure
	// subsequent calls still work
	result2 := service.GetDefaultModel(ctx, model.ProviderAnthropic)
	assert.True(t, result2.IsOk())
}

func TestModelResolverService_ClearExpiredCache(t *testing.T) {
	ctx := context.Background()
	service := NewModelResolverService(50 * time.Millisecond)

	// Populate cache
	result := service.GetDefaultModel(ctx, model.ProviderAnthropic)
	assert.True(t, result.IsOk())

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Clear expired entries
	service.ClearExpiredCache()

	// Verify subsequent calls still work
	result2 := service.GetDefaultModel(ctx, model.ProviderAnthropic)
	assert.True(t, result2.IsOk())
}

func TestModelResolverService_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	service := NewModelResolverService(1 * time.Hour)

	// Test concurrent access to ensure thread safety
	const numGoroutines = 10
	const numIterations = 5

	results := make(chan string, numGoroutines*numIterations)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < numIterations; j++ {
				result := service.GetDefaultModel(ctx, model.ProviderAnthropic)
				if result.IsOk() {
					results <- result.Unwrap()
				}
			}
		}()
	}

	// Collect all results
	var models []string
	for i := 0; i < numGoroutines*numIterations; i++ {
		select {
		case model := <-results:
			models = append(models, model)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}

	// All results should be the same
	assert.Len(t, models, numGoroutines*numIterations)
	expected := "claude-3-5-sonnet-20241022"
	for _, model := range models {
		assert.Equal(t, expected, model)
	}
}

func TestModelResolverService_ProviderSpecificLogic(t *testing.T) {
	ctx := context.Background()
	service := NewModelResolverService(1 * time.Hour)

	// Test that each provider returns models from the correct family
	providers := []struct {
		provider      model.Provider
		expectedFamily string
	}{
		{model.ProviderAnthropic, "claude"},
		{model.ProviderOpenAI, "gpt"},
		{model.ProviderGoogle, "gemini"},
		{model.ProviderCohere, "command"},
	}

	for _, p := range providers {
		t.Run(string(p.provider), func(t *testing.T) {
			result := service.GetAvailableModels(ctx, p.provider)
			assert.True(t, result.IsOk())

			models := result.Unwrap()
			assert.NotEmpty(t, models)

			// Check that at least one model has the expected family
			hasExpectedFamily := false
			for _, m := range models {
				if m.Family == p.expectedFamily {
					hasExpectedFamily = true
					break
				}
			}
			assert.True(t, hasExpectedFamily, "Should have models from family %s", p.expectedFamily)
		})
	}
}

func TestModelResolverService_FallbackBehavior(t *testing.T) {
	ctx := context.Background()
	service := NewModelResolverService(1 * time.Hour)

	// Test that hardcoded fallbacks work when langchaingo fails
	// This test verifies the fallback logic in getHardcodedDefault

	// We can't easily simulate langchaingo failure, but we can test
	// that the hardcoded defaults return expected values
	result := service.GetDefaultModel(ctx, model.ProviderAnthropic)
	assert.True(t, result.IsOk())
	assert.Equal(t, "claude-3-5-sonnet-20241022", result.Unwrap())
}

func TestModelInfo_HelperMethods(t *testing.T) {
	tests := []struct {
		name       string
		modelInfo  model.ModelInfo
		isAdvanced bool
		isLegacy   bool
		displayName string
	}{
		{
			name: "advanced model with display name",
			modelInfo: model.ModelInfo{
				ModelID:     "test-model",
				DisplayName: "Test Model",
				Capability:  model.ModelCapabilityAdvanced,
			},
			isAdvanced:  true,
			isLegacy:    false,
			displayName: "Test Model",
		},
		{
			name: "legacy model without display name",
			modelInfo: model.ModelInfo{
				ModelID:    "legacy-model",
				Capability: model.ModelCapabilityLegacy,
			},
			isAdvanced:  false,
			isLegacy:    true,
			displayName: "legacy-model",
		},
		{
			name: "standard model",
			modelInfo: model.ModelInfo{
				ModelID:    "standard-model",
				Capability: model.ModelCapabilityStandard,
			},
			isAdvanced:  false,
			isLegacy:    false,
			displayName: "standard-model",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isAdvanced, tt.modelInfo.IsAdvanced())
			assert.Equal(t, tt.isLegacy, tt.modelInfo.IsLegacy())
			assert.Equal(t, tt.displayName, tt.modelInfo.GetDisplayName())
		})
	}
}