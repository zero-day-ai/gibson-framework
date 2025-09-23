// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package providers

import (
	"testing"

	"github.com/gibson-sec/gibson-framework-2/internal/model"
	"github.com/stretchr/testify/assert"
)

func TestNewProviderAdapter(t *testing.T) {
	adapter := NewProviderAdapter()
	assert.NotNil(t, adapter)
	assert.NotNil(t, adapter.defaultURLs)

	// Check that expected providers have default URLs
	expectedProviders := []string{"anthropic", "openai", "google", "cohere", "huggingface"}
	for _, provider := range expectedProviders {
		url, exists := adapter.defaultURLs[provider]
		assert.True(t, exists, "Provider %s should have a default URL", provider)
		assert.NotEmpty(t, url, "Provider %s should have a non-empty URL", provider)
	}
}

func TestResolveURL(t *testing.T) {
	adapter := NewProviderAdapter()

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
		{
			name:        "custom requires URL",
			provider:    model.ProviderCustom,
			userURL:     "",
			expectedURL: "",
			expectError: true,
		},
		{
			name:        "unknown provider",
			provider:    model.Provider("unknown"),
			userURL:     "",
			expectedURL: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := adapter.ResolveURL(tt.provider, tt.userURL)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedURL, url)
			}
		})
	}
}

func TestValidateLangChainModel(t *testing.T) {
	adapter := NewProviderAdapter()

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
			name:        "valid openai model",
			provider:    model.ProviderOpenAI,
			modelName:   "gpt-4",
			expectError: false,
		},
		{
			name:        "invalid openai model",
			provider:    model.ProviderOpenAI,
			modelName:   "invalid-model",
			expectError: true,
		},
		{
			name:        "empty model name - should pass",
			provider:    model.ProviderAnthropic,
			modelName:   "",
			expectError: false,
		},
		{
			name:        "huggingface model - should pass (diverse models)",
			provider:    model.ProviderHuggingFace,
			modelName:   "any-model-name",
			expectError: false,
		},
		{
			name:        "custom provider model - should pass",
			provider:    model.ProviderCustom,
			modelName:   "any-model",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := adapter.ValidateLangChainModel(tt.provider, tt.modelName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAnthropicModel(t *testing.T) {
	adapter := NewProviderAdapter()

	validModels := []string{
		"claude-3-5-sonnet-20241022",
		"claude-3-opus-20240229",
		"claude-2.1",
	}

	invalidModels := []string{
		"gpt-4",
		"invalid-model",
		"claude-invalid",
	}

	for _, model := range validModels {
		t.Run("valid_"+model, func(t *testing.T) {
			err := adapter.validateAnthropicModel(model)
			assert.NoError(t, err)
		})
	}

	for _, model := range invalidModels {
		t.Run("invalid_"+model, func(t *testing.T) {
			err := adapter.validateAnthropicModel(model)
			assert.Error(t, err)
		})
	}
}

func TestValidateOpenAIModel(t *testing.T) {
	adapter := NewProviderAdapter()

	validModels := []string{
		"gpt-4",
		"gpt-4-turbo",
		"gpt-3.5-turbo",
	}

	invalidModels := []string{
		"claude-3-opus",
		"invalid-model",
		"gpt-invalid",
	}

	for _, model := range validModels {
		t.Run("valid_"+model, func(t *testing.T) {
			err := adapter.validateOpenAIModel(model)
			assert.NoError(t, err)
		})
	}

	for _, model := range invalidModels {
		t.Run("invalid_"+model, func(t *testing.T) {
			err := adapter.validateOpenAIModel(model)
			assert.Error(t, err)
		})
	}
}

func TestGetDefaultURL(t *testing.T) {
	adapter := NewProviderAdapter()

	tests := []struct {
		name           string
		provider       model.Provider
		expectedURL    string
		expectedExists bool
	}{
		{
			name:           "anthropic has default",
			provider:       model.ProviderAnthropic,
			expectedURL:    "https://api.anthropic.com/v1/messages",
			expectedExists: true,
		},
		{
			name:           "openai has default",
			provider:       model.ProviderOpenAI,
			expectedURL:    "https://api.openai.com/v1/chat/completions",
			expectedExists: true,
		},
		{
			name:           "azure has no default",
			provider:       model.ProviderAzure,
			expectedURL:    "",
			expectedExists: false,
		},
		{
			name:           "custom has no default",
			provider:       model.ProviderCustom,
			expectedURL:    "",
			expectedExists: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, exists := adapter.GetDefaultURL(tt.provider)
			assert.Equal(t, tt.expectedExists, exists)
			if tt.expectedExists {
				assert.Equal(t, tt.expectedURL, url)
			}
		})
	}
}

func TestIsKnownProvider(t *testing.T) {
	adapter := NewProviderAdapter()

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
		t.Run("known_"+string(provider), func(t *testing.T) {
			assert.True(t, adapter.IsKnownProvider(provider))
		})
	}

	unknownProviders := []model.Provider{
		model.Provider("unknown"),
		model.Provider("invalid"),
		model.Provider(""),
	}

	for _, provider := range unknownProviders {
		t.Run("unknown_"+string(provider), func(t *testing.T) {
			assert.False(t, adapter.IsKnownProvider(provider))
		})
	}
}