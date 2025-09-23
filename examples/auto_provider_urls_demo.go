// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

// Package main demonstrates the auto-provider-urls feature
package main

import (
	"fmt"

	"github.com/gibson-sec/gibson-framework-2/internal/model"
	"github.com/gibson-sec/gibson-framework-2/internal/providers"
)

func main() {
	fmt.Println("Gibson Framework Auto-Provider-URLs Demo")
	fmt.Println("========================================")

	// Create a provider registry
	registry := providers.NewRegistry()

	// Demo 1: Show default URLs for known providers
	fmt.Println("\n1. Default URLs for known providers:")
	providerURLs := map[model.Provider]string{
		model.ProviderAnthropic:   "",
		model.ProviderOpenAI:      "",
		model.ProviderGoogle:      "",
		model.ProviderCohere:      "",
		model.ProviderHuggingFace: "",
		model.ProviderAzure:       "",
		model.ProviderCustom:      "",
		model.ProviderOllama:      "",
	}

	for provider := range providerURLs {
		if url, exists := registry.GetDefaultURL(provider); exists {
			fmt.Printf("   %s: %s\n", provider, url)
		} else {
			fmt.Printf("   %s: (requires custom URL)\n", provider)
		}
	}

	// Demo 2: URL resolution with and without user URLs
	fmt.Println("\n2. URL Resolution Examples:")

	// Without user URL (uses default)
	anthroricURL, err := registry.ResolveURL(model.ProviderAnthropic, "")
	if err != nil {
		fmt.Printf("   Anthropic (no URL): ERROR - %v\n", err)
	} else {
		fmt.Printf("   Anthropic (no URL): %s\n", anthroricURL)
	}

	// With user URL (uses provided URL)
	customURL := "https://my-custom-anthropic.com/api"
	resolvedURL, err := registry.ResolveURL(model.ProviderAnthropic, customURL)
	if err != nil {
		fmt.Printf("   Anthropic (custom URL): ERROR - %v\n", err)
	} else {
		fmt.Printf("   Anthropic (custom URL): %s\n", resolvedURL)
	}

	// Azure requires URL
	_, err = registry.ResolveURL(model.ProviderAzure, "")
	if err != nil {
		fmt.Printf("   Azure (no URL): ERROR - %v\n", err)
	}

	// Demo 3: Model validation
	fmt.Println("\n3. Model Validation Examples:")

	validationTests := []struct {
		provider model.Provider
		model    string
	}{
		{model.ProviderAnthropic, "claude-3-opus-20240229"},
		{model.ProviderAnthropic, "gpt-4"},
		{model.ProviderOpenAI, "gpt-4"},
		{model.ProviderOpenAI, "claude-3-opus-20240229"},
		{model.ProviderHuggingFace, "any-model-name"},
		{model.ProviderCustom, "my-custom-model"},
	}

	for _, test := range validationTests {
		err := registry.ValidateModel(test.provider, test.model)
		if err != nil {
			fmt.Printf("   %s/%s: WARNING - %v\n", test.provider, test.model, err)
		} else {
			fmt.Printf("   %s/%s: ✓ Valid\n", test.provider, test.model)
		}
	}

	// Demo 4: Supported providers
	fmt.Println("\n4. All Supported Providers:")
	supportedProviders := registry.GetSupportedProviders()
	for i, provider := range supportedProviders {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Print(provider)
	}
	fmt.Println()

	// Demo 5: Error handling
	fmt.Println("\n5. Error Handling Examples:")

	// Unknown provider
	unknownProvider := model.Provider("unknown-provider")
	err = registry.CreateProviderError(unknownProvider)
	fmt.Printf("   Unknown provider error: %v\n", err)

	// Azure provider error
	err = registry.CreateProviderError(model.ProviderAzure)
	fmt.Printf("   Azure provider error: %v\n", err)

	fmt.Println("\nDemo completed! This shows how the auto-provider-urls feature")
	fmt.Println("automatically resolves API URLs for known providers while allowing")
	fmt.Println("users to override with custom URLs when needed.")
}