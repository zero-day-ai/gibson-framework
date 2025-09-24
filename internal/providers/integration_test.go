// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package providers

import (
	"testing"

	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/stretchr/testify/assert"
)

// TestProviderIntegration demonstrates the full auto-provider-urls workflow
func TestProviderIntegration(t *testing.T) {
	registry := NewRegistry()

	// Test case 1: User provides no URL, should get default
	t.Run("AnthropicDefaultURL", func(t *testing.T) {
		resolvedURL, err := registry.ResolveURL(model.ProviderAnthropic, "")
		assert.NoError(t, err)
		assert.Equal(t, "https://api.anthropic.com/v1/messages", resolvedURL)
	})

	// Test case 2: User provides URL, should use user URL
	t.Run("UserProvidedURL", func(t *testing.T) {
		customURL := "https://my-custom-anthropic.com/v1/chat"
		resolvedURL, err := registry.ResolveURL(model.ProviderAnthropic, customURL)
		assert.NoError(t, err)
		assert.Equal(t, customURL, resolvedURL)
	})

	// Test case 3: Azure requires URL
	t.Run("AzureRequiresURL", func(t *testing.T) {
		_, err := registry.ResolveURL(model.ProviderAzure, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "URL is required")
	})

	// Test case 4: Azure with URL works
	t.Run("AzureWithURL", func(t *testing.T) {
		azureURL := "https://my-azure-resource.openai.azure.com/openai/deployments/gpt-4/chat/completions"
		resolvedURL, err := registry.ResolveURL(model.ProviderAzure, azureURL)
		assert.NoError(t, err)
		assert.Equal(t, azureURL, resolvedURL)
	})

	// Test case 5: Model validation
	t.Run("ModelValidation", func(t *testing.T) {
		// Valid model
		err := registry.ValidateModel(model.ProviderAnthropic, "claude-3-opus-20240229")
		assert.NoError(t, err)

		// Invalid model (should warn, not fail)
		err = registry.ValidateModel(model.ProviderAnthropic, "invalid-model")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "may not be a valid")
	})

	// Test case 6: All supported providers
	t.Run("AllSupportedProviders", func(t *testing.T) {
		providers := registry.GetSupportedProviders()
		expectedCount := 8 // anthropic, openai, google, cohere, huggingface, azure, custom, ollama

		assert.Len(t, providers, expectedCount)
		assert.Contains(t, providers, model.ProviderAnthropic)
		assert.Contains(t, providers, model.ProviderOpenAI)
		assert.Contains(t, providers, model.ProviderGoogle)
		assert.Contains(t, providers, model.ProviderCohere)
		assert.Contains(t, providers, model.ProviderHuggingFace)
		assert.Contains(t, providers, model.ProviderAzure)
		assert.Contains(t, providers, model.ProviderCustom)
		assert.Contains(t, providers, model.ProviderOllama)
	})

	// Test case 7: Caching works
	t.Run("URLCaching", func(t *testing.T) {
		// Clear cache first
		registry.ClearCache()
		assert.Equal(t, 0, registry.GetCacheSize())

		// First call should populate cache
		url1, err1 := registry.ResolveURL(model.ProviderOpenAI, "")
		assert.NoError(t, err1)
		assert.Equal(t, 1, registry.GetCacheSize())

		// Second call should use cache
		url2, err2 := registry.ResolveURL(model.ProviderOpenAI, "")
		assert.NoError(t, err2)
		assert.Equal(t, url1, url2)
		assert.Equal(t, 1, registry.GetCacheSize())
	})
}

// TestProviderErrorMessages tests that error messages are helpful
func TestProviderErrorMessages(t *testing.T) {
	registry := NewRegistry()

	tests := []struct {
		name            string
		provider        model.Provider
		expectedMessage string
	}{
		{
			name:            "azure provider error",
			provider:        model.ProviderAzure,
			expectedMessage: "provider 'azure' requires a custom URL",
		},
		{
			name:            "unknown provider error",
			provider:        model.Provider("unknown"),
			expectedMessage: "unsupported provider 'unknown'. Supported providers:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := registry.CreateProviderError(tt.provider)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedMessage)
		})
	}
}

// TestModelValidationIntegration tests the model validation workflow
func TestModelValidationIntegration(t *testing.T) {
	registry := NewRegistry()

	// Test various provider/model combinations
	testCases := []struct {
		provider    model.Provider
		model       string
		shouldError bool
		description string
	}{
		{model.ProviderAnthropic, "claude-3-opus-20240229", false, "valid Anthropic model"},
		{model.ProviderAnthropic, "gpt-4", true, "OpenAI model on Anthropic provider"},
		{model.ProviderOpenAI, "gpt-4", false, "valid OpenAI model"},
		{model.ProviderOpenAI, "claude-3-opus-20240229", true, "Anthropic model on OpenAI provider"},
		{model.ProviderHuggingFace, "some-random-model", false, "HuggingFace allows any model"},
		{model.ProviderCustom, "any-model", false, "Custom provider allows any model"},
		{model.ProviderGoogle, "gemini-pro", false, "valid Google model"},
		{model.ProviderCohere, "command", false, "valid Cohere model"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			err := registry.ValidateModel(tc.provider, tc.model)
			if tc.shouldError {
				assert.Error(t, err, "Expected error for %s/%s", tc.provider, tc.model)
			} else {
				assert.NoError(t, err, "Expected no error for %s/%s", tc.provider, tc.model)
			}
		})
	}
}