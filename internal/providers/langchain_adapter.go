// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package providers

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/model"
	"github.com/gibson-sec/gibson-framework-2/pkg/core/models"
	modelservice "github.com/gibson-sec/gibson-framework-2/pkg/services/model"
)

// ProviderAdapter provides langchaingo-based provider URL resolution and model defaulting
type ProviderAdapter struct {
	defaultURLs       map[string]string
	modelResolver     *modelservice.ModelResolverService
}

// NewProviderAdapter creates a new provider adapter with default URLs and model resolution
func NewProviderAdapter() *ProviderAdapter {
	return &ProviderAdapter{
		defaultURLs: map[string]string{
			"anthropic":   "https://api.anthropic.com/v1/messages",
			"openai":      "https://api.openai.com/v1/chat/completions",
			"google":      "https://generativelanguage.googleapis.com/v1beta",
			"cohere":      "https://api.cohere.ai/v1/chat",
			"huggingface": "https://api-inference.huggingface.co/models",
			// Azure and custom require custom URLs
		},
		modelResolver: modelservice.NewModelResolverService(24 * time.Hour),
	}
}

// ResolveURL returns the appropriate URL for a provider
// If userURL is provided, it takes precedence over defaults
func (pa *ProviderAdapter) ResolveURL(provider model.Provider, userURL string) (string, error) {
	// If user provided a URL, use it
	if userURL != "" {
		return userURL, nil
	}

	// Convert provider to lowercase string for lookup
	providerStr := strings.ToLower(string(provider))

	// Check if we have a default URL for this provider
	if defaultURL, exists := pa.defaultURLs[providerStr]; exists {
		return defaultURL, nil
	}

	// For Azure and Custom providers, URL is required
	if provider == model.ProviderAzure || provider == model.ProviderCustom {
		return "", fmt.Errorf("URL is required for provider '%s'", provider)
	}

	// For unknown providers, return error
	return "", fmt.Errorf("no default URL available for provider '%s', please specify --url", provider)
}

// ValidateLangChainModel validates model names against known patterns
func (pa *ProviderAdapter) ValidateLangChainModel(provider model.Provider, modelName string) error {
	if modelName == "" {
		// Model is optional for some providers
		return nil
	}

	providerStr := strings.ToLower(string(provider))

	switch providerStr {
	case "anthropic":
		return pa.validateAnthropicModel(modelName)
	case "openai":
		return pa.validateOpenAIModel(modelName)
	case "google":
		return pa.validateGoogleModel(modelName)
	case "cohere":
		return pa.validateCohereModel(modelName)
	case "huggingface":
		// HuggingFace models are too diverse to validate strictly
		return nil
	case "azure":
		// Azure models depend on deployment
		return nil
	case "custom", "ollama":
		// Custom and Ollama models are user-defined
		return nil
	default:
		// For unknown providers, skip validation
		return nil
	}
}

// validateAnthropicModel validates Anthropic model names
func (pa *ProviderAdapter) validateAnthropicModel(modelName string) error {
	validModels := map[string]bool{
		"claude-3-5-sonnet-20241022": true,
		"claude-3-5-sonnet-20240620": true,
		"claude-3-opus-20240229":     true,
		"claude-3-sonnet-20240229":   true,
		"claude-3-haiku-20240307":    true,
		"claude-2.1":                 true,
		"claude-2.0":                 true,
		"claude-instant-1.2":         true,
	}

	if !validModels[modelName] {
		// Return warning-level error (caller can decide to warn vs fail)
		return fmt.Errorf("model '%s' may not be a valid Anthropic model", modelName)
	}

	return nil
}

// validateOpenAIModel validates OpenAI model names
func (pa *ProviderAdapter) validateOpenAIModel(modelName string) error {
	validModels := map[string]bool{
		"gpt-4":                  true,
		"gpt-4-turbo":           true,
		"gpt-4-turbo-preview":   true,
		"gpt-4-vision-preview":  true,
		"gpt-4-1106-preview":    true,
		"gpt-4-0125-preview":    true,
		"gpt-3.5-turbo":         true,
		"gpt-3.5-turbo-1106":    true,
		"gpt-3.5-turbo-instruct": true,
		"davinci-002":           true,
		"babbage-002":           true,
	}

	if !validModels[modelName] {
		return fmt.Errorf("model '%s' may not be a valid OpenAI model", modelName)
	}

	return nil
}

// validateGoogleModel validates Google model names
func (pa *ProviderAdapter) validateGoogleModel(modelName string) error {
	validModels := map[string]bool{
		"gemini-pro":         true,
		"gemini-pro-vision":  true,
		"gemini-ultra":       true,
		"text-bison-001":     true,
		"chat-bison-001":     true,
		"code-bison-001":     true,
	}

	if !validModels[modelName] {
		return fmt.Errorf("model '%s' may not be a valid Google model", modelName)
	}

	return nil
}

// validateCohereModel validates Cohere model names
func (pa *ProviderAdapter) validateCohereModel(modelName string) error {
	validModels := map[string]bool{
		"command":           true,
		"command-light":     true,
		"command-nightly":   true,
		"command-r":         true,
		"command-r-plus":    true,
	}

	if !validModels[modelName] {
		return fmt.Errorf("model '%s' may not be a valid Cohere model", modelName)
	}

	return nil
}

// GetDefaultURL returns the default URL for a provider without resolution logic
func (pa *ProviderAdapter) GetDefaultURL(provider model.Provider) (string, bool) {
	providerStr := strings.ToLower(string(provider))
	url, exists := pa.defaultURLs[providerStr]
	return url, exists
}

// IsKnownProvider returns true if the provider has langchaingo support
func (pa *ProviderAdapter) IsKnownProvider(provider model.Provider) bool {
	switch provider {
	case model.ProviderAnthropic, model.ProviderOpenAI, model.ProviderGoogle,
		 model.ProviderCohere, model.ProviderHuggingFace, model.ProviderAzure,
		 model.ProviderCustom, model.ProviderOllama:
		return true
	default:
		return false
	}
}

// ResolveModelWithDefault returns the specified model or defaults to the latest for the provider
func (pa *ProviderAdapter) ResolveModelWithDefault(ctx context.Context, provider model.Provider, userModel string) models.Result[string] {
	// If user provided a model, validate and use it
	if userModel != "" {
		// Validate the model first
		if err := pa.ValidateLangChainModel(provider, userModel); err != nil {
			// Return warning but still allow the model
			// This maintains backward compatibility while providing feedback
		}
		return models.Ok(userModel)
	}

	// Get default model for provider using model resolver
	return pa.modelResolver.GetDefaultModel(ctx, provider)
}

// GetLatestModel returns the latest/best model for a provider
func (pa *ProviderAdapter) GetLatestModel(ctx context.Context, provider model.Provider) models.Result[string] {
	return pa.modelResolver.GetDefaultModel(ctx, provider)
}

// GetAvailableModels returns all available models for a provider
func (pa *ProviderAdapter) GetAvailableModels(ctx context.Context, provider model.Provider) models.Result[[]model.ModelInfo] {
	return pa.modelResolver.GetAvailableModels(ctx, provider)
}

// ValidateModel validates if a model exists for the given provider
func (pa *ProviderAdapter) ValidateModel(ctx context.Context, provider model.Provider, modelID string) models.Result[bool] {
	return pa.modelResolver.ValidateModel(ctx, provider, modelID)
}