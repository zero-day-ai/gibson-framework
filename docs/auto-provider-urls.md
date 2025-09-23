# Auto-Provider-URLs Feature

The Gibson Framework now includes automatic provider URL resolution using langchaingo patterns. This feature eliminates the need for users to manually specify standard API endpoints for known providers.

## Overview

The auto-provider-urls feature automatically resolves API URLs for known AI/ML providers, falling back to user-provided URLs when needed. This makes it easier to add targets without memorizing specific API endpoints.

## Supported Providers

| Provider | Default URL | Notes |
|----------|------------|-------|
| anthropic | `https://api.anthropic.com/v1/messages` | Claude API |
| openai | `https://api.openai.com/v1/chat/completions` | OpenAI GPT API |
| google | `https://generativelanguage.googleapis.com/v1beta` | Google Gemini API |
| cohere | `https://api.cohere.ai/v1/chat` | Cohere API |
| huggingface | `https://api-inference.huggingface.co/models` | HuggingFace Inference API |
| azure | *(requires custom URL)* | Azure OpenAI Service |
| custom | *(requires custom URL)* | Custom providers |
| ollama | *(requires custom URL)* | Local Ollama instances |

## Usage Examples

### Basic Usage (Using Default URLs)

```bash
# Add Anthropic target - URL is automatically resolved
gibson target add my-anthropic-target --provider anthropic --model claude-3-opus-20240229 --api-key <credential-id>

# Add OpenAI target - URL is automatically resolved
gibson target add my-openai-target --provider openai --model gpt-4 --api-key <credential-id>
```

### Custom URL Override

```bash
# Override default URL with custom endpoint
gibson target add my-custom-anthropic --provider anthropic --url https://my-proxy.com/anthropic --api-key <credential-id>

# Azure requires custom URL
gibson target add my-azure-target --provider azure --url https://my-resource.openai.azure.com/openai/deployments/gpt-4/chat/completions --api-key <credential-id>
```

## Features

### 1. Automatic URL Resolution
- **Default URLs**: Known providers get standard API endpoints automatically
- **User Override**: The `--url` flag always takes precedence
- **Error Handling**: Clear error messages for providers requiring custom URLs

### 2. Model Validation
- **Provider-Specific**: Validates model names against known patterns
- **Warning System**: Invalid models show warnings but don't fail
- **Flexible**: HuggingFace and custom providers allow any model names

### 3. Thread-Safe Caching
- **Performance**: URL resolutions are cached for better performance
- **Thread Safety**: Uses `sync.RWMutex` for concurrent access
- **Cache Management**: Provides cache size monitoring and clearing

### 4. Enhanced Error Messages
- **Helpful Errors**: Lists supported providers for unknown ones
- **Context-Aware**: Different error messages for different scenarios
- **User Guidance**: Suggests using `--url` flag when needed

## Implementation Details

### Core Components

1. **ProviderAdapter** (`internal/providers/langchain_adapter.go`)
   - Maps providers to default URLs
   - Validates model names per provider
   - Handles provider-specific logic

2. **Registry** (`internal/providers/registry.go`)
   - Thread-safe URL resolution with caching
   - Provider validation and error handling
   - Management interface for providers

3. **View Integration** (`internal/view/target.go`)
   - Integrates provider registry into target creation
   - Shows informational messages for default URLs
   - Provides model validation warnings

### Backward Compatibility

- **Existing Targets**: Continue to work without changes
- **URL Flag**: Still functions normally for custom endpoints
- **API Compatibility**: No breaking changes to existing interfaces

## User Experience Improvements

### Before Auto-Provider-URLs
```bash
# User had to know and specify exact URLs
gibson target add my-target --provider anthropic --url https://api.anthropic.com/v1/messages --model claude-3-opus --api-key <key>
```

### After Auto-Provider-URLs
```bash
# URL is automatically resolved and user is informed
gibson target add my-target --provider anthropic --model claude-3-opus --api-key <key>
# Output: ℹ️  Using langchaingo default URL for provider 'anthropic': https://api.anthropic.com/v1/messages
```

## Testing

The feature includes comprehensive tests:
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end workflow testing
- **Error Handling**: Validation of error scenarios
- **Demo**: Interactive demonstration of functionality

Run tests with:
```bash
go test ./internal/providers/... -v
```

## Dependencies

- **langchaingo**: Added as dependency for provider patterns
- **No Breaking Changes**: Maintains compatibility with existing code
- **Thread-Safe**: Uses Go's sync primitives for concurrency

## Future Enhancements

1. **Dynamic Provider Loading**: Support for plugin-based provider extensions
2. **Configuration Files**: Provider URL customization via config files
3. **Health Checking**: Automatic validation of provider endpoints
4. **Rate Limiting**: Provider-specific request throttling
5. **Metrics**: Usage statistics and performance monitoring