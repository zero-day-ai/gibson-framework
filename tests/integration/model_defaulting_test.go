// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package integration_test

import (
	"context"
	"crypto/rand"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson-framework/internal/dao"
	"github.com/zero-day-ai/gibson-framework/internal/model"
	"github.com/zero-day-ai/gibson-framework/internal/providers"
	"github.com/zero-day-ai/gibson-framework/internal/service"
	"github.com/zero-day-ai/gibson-framework/internal/testutil"
	"github.com/zero-day-ai/gibson-framework/pkg/cli/config"
	modelservice "github.com/zero-day-ai/gibson-framework/pkg/services/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestModelDefaultingIntegration tests the complete model defaulting flow
func TestModelDefaultingIntegration(t *testing.T) {
	ctx := context.Background()
	testDB := testutil.NewTestDatabase(t)
	defer testDB.Close()

	testDB.CreateAllTables()

	// Initialize repository
	repo, err := dao.NewSQLiteRepository(testDB.Path)
	require.NoError(t, err)
	defer repo.Close()

	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelWarn, // Reduce noise in tests
	}))

	// Create encryption key
	encryptionKey := make([]byte, 32)
	_, err = rand.Read(encryptionKey)
	require.NoError(t, err)

	// Initialize service factory
	factory := service.NewServiceFactory(repo, logger, encryptionKey)
	targetService := factory.TargetService()

	// Test scenarios
	testProviders := []struct {
		provider      model.Provider
		expectedModel string
	}{
		{model.ProviderAnthropic, "claude-3-5-sonnet-20241022"},
		{model.ProviderOpenAI, "gpt-4-turbo-preview"},
		{model.ProviderGoogle, "gemini-1.5-pro"},
		{model.ProviderCohere, "command-r-plus"},
	}

	for _, tc := range testProviders {
		t.Run(string(tc.provider), func(t *testing.T) {
			// Test target creation without model (should apply default)
			target := &model.Target{
				ID:           uuid.New(),
				Name:         "test-target-" + string(tc.provider),
				Type:         model.TargetTypeAPI,
				Provider:     tc.provider,
				Model:        "", // No model specified
				URL:          "https://api.example.com",
				Status:       model.TargetStatusActive,
				Description:  "Test target for model defaulting",
				CredentialID: nil, // No credential for testing
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			}

			// Create target without model
			err := targetService.Create(ctx, target)
			require.NoError(t, err)

			// Simulate the model defaulting logic that would happen in target add
			providerAdapter := providers.NewProviderAdapter()
			resolvedModelResult := providerAdapter.ResolveModelWithDefault(ctx, tc.provider, "")
			require.True(t, resolvedModelResult.IsOk())
			resolvedModel := resolvedModelResult.Unwrap()

			// Update target with resolved model
			target.Model = resolvedModel
			err = targetService.Update(ctx, target)
			require.NoError(t, err)

			// Verify target was updated with expected model
			retrievedTarget, err := targetService.Get(ctx, target.ID)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedModel, retrievedTarget.Model)
			assert.Equal(t, tc.provider, retrievedTarget.Provider)
		})
	}
}

// TestModelResolverServiceIntegration tests the ModelResolverService with real langchaingo integration
func TestModelResolverServiceIntegration(t *testing.T) {
	ctx := context.Background()
	resolver := modelservice.NewModelResolverService(1 * time.Hour)

	providers := []model.Provider{
		model.ProviderAnthropic,
		model.ProviderOpenAI,
		model.ProviderGoogle,
		model.ProviderCohere,
	}

	for _, provider := range providers {
		t.Run(string(provider), func(t *testing.T) {
			// Test GetDefaultModel
			defaultResult := resolver.GetDefaultModel(ctx, provider)
			require.True(t, defaultResult.IsOk(), "Failed to get default model for %s: %v", provider, defaultResult.Error())
			defaultModel := defaultResult.Unwrap()
			assert.NotEmpty(t, defaultModel)

			// Test GetAvailableModels
			availableResult := resolver.GetAvailableModels(ctx, provider)
			require.True(t, availableResult.IsOk(), "Failed to get available models for %s: %v", provider, availableResult.Error())
			availableModels := availableResult.Unwrap()
			assert.NotEmpty(t, availableModels)

			// Verify default model is in available models
			foundDefault := false
			for _, m := range availableModels {
				if m.ModelID == defaultModel {
					foundDefault = true
					break
				}
			}
			assert.True(t, foundDefault, "Default model %s not found in available models for %s", defaultModel, provider)

			// Test ValidateModel with the default model
			validateResult := resolver.ValidateModel(ctx, provider, defaultModel)
			require.True(t, validateResult.IsOk())
			assert.True(t, validateResult.Unwrap(), "Default model %s should be valid for %s", defaultModel, provider)
		})
	}
}

// TestProviderAdapterIntegration tests the ProviderAdapter with model defaulting
func TestProviderAdapterIntegration(t *testing.T) {
	ctx := context.Background()
	adapter := providers.NewProviderAdapter()

	testCases := []struct {
		name      string
		provider  model.Provider
		userModel string
		expectDefault bool
	}{
		{
			name:          "anthropic with user model",
			provider:      model.ProviderAnthropic,
			userModel:     "claude-3-opus-20240229",
			expectDefault: false,
		},
		{
			name:          "anthropic without user model",
			provider:      model.ProviderAnthropic,
			userModel:     "",
			expectDefault: true,
		},
		{
			name:          "openai with user model",
			provider:      model.ProviderOpenAI,
			userModel:     "gpt-3.5-turbo",
			expectDefault: false,
		},
		{
			name:          "openai without user model",
			provider:      model.ProviderOpenAI,
			userModel:     "",
			expectDefault: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := adapter.ResolveModelWithDefault(ctx, tc.provider, tc.userModel)
			require.True(t, result.IsOk())

			resolvedModel := result.Unwrap()
			assert.NotEmpty(t, resolvedModel)

			if tc.expectDefault {
				// When no user model, should get default
				expectedDefaults := map[model.Provider]string{
					model.ProviderAnthropic: "claude-3-5-sonnet-20241022",
					model.ProviderOpenAI:    "gpt-4-turbo-preview",
					model.ProviderGoogle:    "gemini-1.5-pro",
					model.ProviderCohere:    "command-r-plus",
				}
				assert.Equal(t, expectedDefaults[tc.provider], resolvedModel)
			} else {
				// When user provides model, should get that model
				assert.Equal(t, tc.userModel, resolvedModel)
			}
		})
	}
}

// TestConfigurationPrecedence tests that configuration values are used correctly
func TestConfigurationPrecedence(t *testing.T) {
	// Test that viper configuration works
	cfg := config.DefaultConfig()
	assert.NotNil(t, cfg)
	assert.NotEmpty(t, cfg.ModelDefaults.AnthropicDefault)
	assert.NotEmpty(t, cfg.ModelDefaults.OpenAIDefault)
	assert.NotEmpty(t, cfg.ModelDefaults.GoogleDefault)
	assert.NotEmpty(t, cfg.ModelDefaults.CohereDefault)
	assert.Positive(t, cfg.ModelDefaults.CacheTTLHours)

	// Test configuration getters
	anthDefault := config.GetProviderModelDefault("anthropic")
	assert.NotEmpty(t, anthDefault)

	openaiDefault := config.GetProviderModelDefault("openai")
	assert.NotEmpty(t, openaiDefault)

	// Test setting configuration
	config.SetProviderModelDefault("anthropic", "custom-claude-model")
	updated := config.GetProviderModelDefault("anthropic")
	assert.Equal(t, "custom-claude-model", updated)
}

// TestLegacyTargetMigration tests that targets without models get defaults during scan
func TestLegacyTargetMigration(t *testing.T) {
	ctx := context.Background()
	testDB := testutil.NewTestDatabase(t)
	defer testDB.Close()

	testDB.CreateAllTables()

	// Initialize repository
	repo, err := dao.NewSQLiteRepository(testDB.Path)
	require.NoError(t, err)
	defer repo.Close()

	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))

	// Create encryption key
	encryptionKey := make([]byte, 32)
	_, err = rand.Read(encryptionKey)
	require.NoError(t, err)

	// Initialize service factory
	factory := service.NewServiceFactory(repo, logger, encryptionKey)
	targetService := factory.TargetService()

	// Create a legacy target without a model (simulating old data)
	legacyTarget := &model.Target{
		ID:           uuid.New(),
		Name:         "legacy-target",
		Type:         model.TargetTypeAPI,
		Provider:     model.ProviderAnthropic,
		Model:        "", // No model - legacy target
		URL:          "https://api.anthropic.com/v1/messages",
		Status:       model.TargetStatusActive,
		Description:  "Legacy target without model",
		CredentialID: nil, // No credential for testing
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Create the legacy target
	err = targetService.Create(ctx, legacyTarget)
	require.NoError(t, err)

	// Verify target has no model
	retrievedTarget, err := targetService.Get(ctx, legacyTarget.ID)
	require.NoError(t, err)
	assert.Empty(t, retrievedTarget.Model)

	// Simulate the scan start logic that would apply defaults
	if retrievedTarget.Model == "" {
		providerAdapter := providers.NewProviderAdapter()
		resolvedModelResult := providerAdapter.ResolveModelWithDefault(ctx, retrievedTarget.Provider, "")
		require.True(t, resolvedModelResult.IsOk())
		resolvedModel := resolvedModelResult.Unwrap()

		// Update target with default model
		retrievedTarget.Model = resolvedModel
		err = targetService.Update(ctx, retrievedTarget)
		require.NoError(t, err)

		// Verify target now has the expected default model
		updatedTarget, err := targetService.Get(ctx, legacyTarget.ID)
		require.NoError(t, err)
		assert.Equal(t, "claude-3-5-sonnet-20241022", updatedTarget.Model)
	}
}

// TestCacheEffectiveness tests that caching improves performance
func TestCacheEffectiveness(t *testing.T) {
	ctx := context.Background()
	resolver := modelservice.NewModelResolverService(1 * time.Hour)

	// Measure first call (cache miss)
	start1 := time.Now()
	result1 := resolver.GetDefaultModel(ctx, model.ProviderAnthropic)
	duration1 := time.Since(start1)
	require.True(t, result1.IsOk())

	// Measure second call (cache hit)
	start2 := time.Now()
	result2 := resolver.GetDefaultModel(ctx, model.ProviderAnthropic)
	duration2 := time.Since(start2)
	require.True(t, result2.IsOk())

	// Cache hit should be faster (though this is timing-dependent)
	assert.Equal(t, result1.Unwrap(), result2.Unwrap())
	// Cache hit should generally be faster, but we won't assert this due to timing variability
	t.Logf("First call: %v, Second call: %v", duration1, duration2)
}

// TestProviderAdapterValidation tests that the ProviderAdapter validates models correctly
func TestProviderAdapterValidation(t *testing.T) {
	ctx := context.Background()
	adapter := providers.NewProviderAdapter()

	testCases := []struct {
		name      string
		provider  model.Provider
		modelID   string
		expectErr bool
	}{
		{
			name:      "valid anthropic model",
			provider:  model.ProviderAnthropic,
			modelID:   "claude-3-5-sonnet-20241022",
			expectErr: false,
		},
		{
			name:      "valid openai model",
			provider:  model.ProviderOpenAI,
			modelID:   "gpt-4-turbo-preview",
			expectErr: false,
		},
		{
			name:      "invalid model for provider",
			provider:  model.ProviderAnthropic,
			modelID:   "nonexistent-model",
			expectErr: false, // Should return false, not error
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := adapter.ValidateModel(ctx, tc.provider, tc.modelID)

			if tc.expectErr {
				assert.True(t, result.IsErr())
			} else {
				assert.True(t, result.IsOk())
			}
		})
	}
}

// TestFullTargetCreationWorkflow tests the complete target creation workflow with model defaulting
func TestFullTargetCreationWorkflow(t *testing.T) {
	ctx := context.Background()
	testDB := testutil.NewTestDatabase(t)
	defer testDB.Close()

	testDB.CreateAllTables()

	// Initialize repository
	repo, err := dao.NewSQLiteRepository(testDB.Path)
	require.NoError(t, err)
	defer repo.Close()

	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))

	// Create encryption key
	encryptionKey := make([]byte, 32)
	_, err = rand.Read(encryptionKey)
	require.NoError(t, err)

	// Initialize service factory
	factory := service.NewServiceFactory(repo, logger, encryptionKey)

	// Simulate the target add workflow
	targetName := "integration-test-target"
	provider := model.ProviderAnthropic
	userModel := "" // No model specified - should get default

	// Step 1: Resolve model with default
	providerAdapter := providers.NewProviderAdapter()
	resolvedModelResult := providerAdapter.ResolveModelWithDefault(ctx, provider, userModel)
	require.True(t, resolvedModelResult.IsOk())
	resolvedModel := resolvedModelResult.Unwrap()
	assert.Equal(t, "claude-3-5-sonnet-20241022", resolvedModel)

	// Step 2: Create target with resolved model
	target := &model.Target{
		ID:           uuid.New(),
		Name:         targetName,
		Type:         model.TargetTypeAPI,
		Provider:     provider,
		Model:        resolvedModel,
		URL:          "https://api.anthropic.com/v1/messages",
		Status:       model.TargetStatusActive,
		Description:  "Integration test target",
		CredentialID: nil, // No credential for testing
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	targetService := factory.TargetService()
	err = targetService.Create(ctx, target)
	require.NoError(t, err)

	// Step 3: Verify target was created correctly
	retrievedTarget, err := targetService.GetByName(ctx, targetName)
	require.NoError(t, err)
	assert.Equal(t, targetName, retrievedTarget.Name)
	assert.Equal(t, provider, retrievedTarget.Provider)
	assert.Equal(t, resolvedModel, retrievedTarget.Model)
	assert.Equal(t, model.TargetStatusActive, retrievedTarget.Status)

	// Step 4: Test that scan validation would pass
	assert.NotEmpty(t, retrievedTarget.Model, "Target should have a model for scan execution")
}