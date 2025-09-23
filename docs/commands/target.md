# Target Commands

The target commands allow you to manage AI/ML targets for security testing. These commands have been enhanced with comprehensive validation for different AI providers and improved credential linkage.

## Table of Contents

- [Overview](#overview)
- [Commands](#commands)
  - [add](#add)
  - [list](#list)
  - [delete](#delete)
  - [test](#test)
  - [update](#update)
  - [info](#info)
- [Provider Configuration](#provider-configuration)
- [Credential Management](#credential-management)
- [Troubleshooting](#troubleshooting)
- [Examples](#examples)

## Overview

Targets represent AI/ML services that Gibson can test for security vulnerabilities. Each target is configured with provider-specific settings, authentication credentials, and connection parameters.

### Key Features

- **Enhanced Provider Validation**: Comprehensive validation for popular AI providers
- **Flexible Credential Linking**: Support for credential names, IDs, or direct API keys
- **Provider-Specific Defaults**: Automatic URL configuration for known providers
- **Connection Testing**: Built-in connectivity and authentication testing
- **Configuration Validation**: Validates URLs, models, and provider-specific requirements

## Commands

### add

Add a new AI/ML target for security testing.

#### Syntax

```bash
gibson target add [NAME] [flags]
```

#### Arguments

- `NAME` - Target name (required)

#### Flags

- `--provider STRING` - AI provider (anthropic, openai, azure, cohere, huggingface, custom) (required)
- `--model STRING` - Model name or ID
- `--url STRING` - API endpoint URL (required for custom providers)
- `--api-key STRING` - API key for authentication
- `--credential STRING` - Credential name or ID to link to this target
- `--config STRING` - Configuration file path
- `--output STRING` - Output format: table, json, yaml (default: "table")

#### Enhanced Validation

The target add command now includes comprehensive validation for different AI providers:

##### Anthropic Targets
- **Default URL**: `https://api.anthropic.com` (if not specified)
- **Required**: API key or credential
- **Valid Models**: claude-3-opus-20240229, claude-3-sonnet-20240229, claude-3-haiku-20240307, claude-2.1, claude-2.0, claude-instant-1.2
- **Validation**: URL format, API key presence, model compatibility

##### OpenAI Targets
- **Default URL**: `https://api.openai.com` (if not specified)
- **Required**: API key or credential
- **Validation**: URL format, API key presence

##### Azure OpenAI Targets
- **Required**: Azure endpoint URL, API key or credential
- **Validation**: URL format (must be Azure endpoint), API key presence

##### Cohere Targets
- **Default URL**: `https://api.cohere.ai` (if not specified)
- **Required**: API key or credential
- **Validation**: URL format, API key presence

##### Hugging Face Targets
- **Default URL**: `https://api-inference.huggingface.co` (if not specified)
- **Required**: API token or credential
- **Validation**: URL format, token presence

##### Custom Providers
- **Required**: URL, API key or credential
- **Validation**: URL format, authentication configuration

#### Credential Linkage

The `--credential` flag supports multiple formats:

1. **Credential Name**: Links to a credential by name
2. **Credential ID**: Links to a credential by UUID
3. **Fallback to API Key**: Uses `--api-key` if `--credential` is not provided

#### Examples

```bash
# Add Anthropic target with credential name
gibson target add claude-sonnet --provider anthropic --model claude-3-sonnet --credential anthropic-api-key

# Add Anthropic target with credential ID
gibson target add claude-opus --provider anthropic --model claude-3-opus --credential 123e4567-e89b-12d3-a456-426614174000

# Add OpenAI target with API key
gibson target add openai-gpt4 --provider openai --model gpt-4 --api-key $OPENAI_API_KEY

# Add Azure OpenAI target
gibson target add azure-gpt4 --provider azure --url https://myservice.openai.azure.com --credential azure-openai-key

# Add custom API target
gibson target add custom-api --provider custom --url https://api.example.com/v1/chat --credential custom-cred

# Add target with config file
gibson target add advanced-target --provider anthropic --config ./target-config.yaml
```

### list

List all configured targets.

#### Syntax

```bash
gibson target list [flags]
```

#### Flags

- `--output STRING` - Output format: table, json, yaml (default: "table")

#### Examples

```bash
# List all targets
gibson target list

# List targets in JSON format
gibson target list --output json
```

### delete

Delete one or more targets.

#### Syntax

```bash
gibson target delete [NAMES...] [flags]
```

#### Arguments

- `NAMES` - Target names to delete (required)

#### Examples

```bash
# Delete a single target
gibson target delete old-target

# Delete multiple targets
gibson target delete target1 target2 target3
```

### test

Test connectivity and authentication for targets.

#### Syntax

```bash
gibson target test [NAMES...] [flags]
```

#### Arguments

- `NAMES` - Target names to test (optional, defaults to all)

#### Examples

```bash
# Test all targets
gibson target test

# Test specific targets
gibson target test claude-sonnet openai-gpt4
```

### update

Update target configuration.

#### Syntax

```bash
gibson target update [NAME] [flags]
```

#### Arguments

- `NAME` - Target name to update (required)

#### Flags

Same as `add` command flags.

#### Examples

```bash
# Update target model
gibson target update claude-sonnet --model claude-3-opus

# Update target credential
gibson target update openai-gpt4 --credential new-openai-key
```

### info

Show detailed information about a target.

#### Syntax

```bash
gibson target info [NAME] [flags]
```

#### Arguments

- `NAME` - Target name (required)

#### Examples

```bash
# Show target information
gibson target info claude-sonnet
```

## Provider Configuration

### Supported Providers

Gibson supports the following AI providers with enhanced validation:

#### Anthropic
- **Provider**: `anthropic`
- **Default URL**: `https://api.anthropic.com`
- **Authentication**: API key required
- **Supported Models**: Claude 3 Opus, Sonnet, Haiku, Claude 2.1, Claude 2.0, Claude Instant

#### OpenAI
- **Provider**: `openai`
- **Default URL**: `https://api.openai.com`
- **Authentication**: API key required
- **Supported Models**: GPT-4, GPT-3.5, and other OpenAI models

#### Azure OpenAI
- **Provider**: `azure`
- **URL**: Must be your Azure OpenAI endpoint
- **Authentication**: Azure API key required
- **Configuration**: Requires Azure-specific endpoint URL

#### Cohere
- **Provider**: `cohere`
- **Default URL**: `https://api.cohere.ai`
- **Authentication**: API key required

#### Hugging Face
- **Provider**: `huggingface`
- **Default URL**: `https://api-inference.huggingface.co`
- **Authentication**: API token required

#### Custom Providers
- **Provider**: `custom`
- **URL**: Required (no default)
- **Authentication**: API key or custom authentication

### Provider-Specific Examples

#### Anthropic Configuration
```bash
# Basic Anthropic target
gibson target add claude-test --provider anthropic --credential anthropic-key

# Anthropic with specific model
gibson target add claude-opus --provider anthropic --model claude-3-opus-20240229 --credential anthropic-key

# Anthropic with custom URL (for proxies)
gibson target add claude-proxy --provider anthropic --url https://proxy.example.com/anthropic --credential anthropic-key
```

#### OpenAI Configuration
```bash
# Basic OpenAI target
gibson target add gpt4-test --provider openai --credential openai-key

# OpenAI with specific model
gibson target add gpt4-turbo --provider openai --model gpt-4-turbo --credential openai-key
```

#### Azure OpenAI Configuration
```bash
# Azure OpenAI target (URL required)
gibson target add azure-gpt4 --provider azure --url https://myservice.openai.azure.com --credential azure-key
```

## Credential Management

### Credential Creation

Before creating targets, create credentials for your AI providers:

```bash
# Create Anthropic credential
gibson credential add anthropic-api-key --provider anthropic --value "your-anthropic-api-key"

# Create OpenAI credential
gibson credential add openai-api-key --provider openai --value "your-openai-api-key"

# Create Azure credential
gibson credential add azure-openai-key --provider azure --value "your-azure-api-key"
```

### Credential Linking Options

When creating targets, you can link credentials in multiple ways:

#### 1. By Credential Name
```bash
gibson target add my-target --provider anthropic --credential anthropic-api-key
```

#### 2. By Credential ID
```bash
gibson target add my-target --provider anthropic --credential 123e4567-e89b-12d3-a456-426614174000
```

#### 3. Direct API Key
```bash
gibson target add my-target --provider anthropic --api-key "your-api-key-here"
```

### Credential Requirements by Provider

| Provider | Credential Type | Required | Notes |
|----------|----------------|----------|-------|
| Anthropic | API Key | Yes | Starts with `sk-ant-` |
| OpenAI | API Key | Yes | Starts with `sk-` |
| Azure | API Key | Yes | Azure-specific key format |
| Cohere | API Key | Yes | Cohere API token |
| Hugging Face | API Token | Yes | HF access token |
| Custom | Variable | Yes | Provider-specific |

## Troubleshooting

### Common Issues and Solutions

#### 1. Validation Failures

**Problem**: Target creation fails with validation errors.

**Solutions**:

For Anthropic targets:
```bash
# Ensure API key is provided
gibson target add claude-test --provider anthropic --credential anthropic-key

# Verify credential exists
gibson credential list --provider anthropic
```

For custom providers:
```bash
# Ensure URL and credential are provided
gibson target add custom-api --provider custom --url https://api.example.com --credential custom-key
```

#### 2. Credential Linking Failures

**Problem**: "no credential found" error when creating targets.

**Solutions**:

Check existing credentials:
```bash
gibson credential list
```

Create missing credential:
```bash
gibson credential add provider-key --provider anthropic --value "your-api-key"
```

Use credential ID instead of name:
```bash
gibson credential list --output json  # Get credential ID
gibson target add my-target --provider anthropic --credential <credential-id>
```

#### 3. Authentication Failures

**Problem**: Target test fails with authentication errors.

**Solutions**:

Verify credential value:
```bash
gibson credential get credential-name --show-value
```

Test credential manually:
```bash
# For Anthropic
curl -H "Authorization: Bearer your-api-key" https://api.anthropic.com/v1/messages

# For OpenAI
curl -H "Authorization: Bearer your-api-key" https://api.openai.com/v1/models
```

Update credential if expired:
```bash
gibson credential update credential-name --value "new-api-key"
```

#### 4. URL Validation Failures

**Problem**: "invalid URL format" error.

**Solutions**:

Ensure URL includes protocol:
```bash
# Correct
gibson target add target --provider custom --url https://api.example.com

# Incorrect
gibson target add target --provider custom --url api.example.com
```

For Azure, use full Azure endpoint:
```bash
gibson target add azure-target --provider azure --url https://myservice.openai.azure.com
```

#### 5. Model Validation Warnings

**Problem**: Warning about unsupported model names.

**Solutions**:

For Anthropic, use supported model names:
```bash
gibson target add claude-test --provider anthropic --model claude-3-sonnet-20240229
```

Check provider documentation for valid model names, or omit model flag to use default.

### Validation Requirements Help

Get detailed validation requirements:

```bash
gibson target add --help
```

This shows validation requirements for each provider including:
- Required fields
- Default URLs
- Credential options
- Model validation

## Examples

### Complete Workflow Example

```bash
# 1. Create credentials for different providers
gibson credential add anthropic-key --provider anthropic --value "sk-ant-your-key"
gibson credential add openai-key --provider openai --value "sk-your-openai-key"
gibson credential add azure-key --provider azure --value "your-azure-key"

# 2. Create targets for different providers
gibson target add claude-sonnet --provider anthropic --model claude-3-sonnet --credential anthropic-key
gibson target add gpt4-turbo --provider openai --model gpt-4-turbo --credential openai-key
gibson target add azure-gpt4 --provider azure --url https://myservice.openai.azure.com --credential azure-key

# 3. Test all targets
gibson target test

# 4. List targets to verify
gibson target list

# 5. Use targets in scans
gibson scan start claude-sonnet --payload-category model
```

### Provider-Specific Examples

#### Enterprise Anthropic Setup
```bash
# Create enterprise credential
gibson credential add anthropic-enterprise --provider anthropic --value "sk-ant-enterprise-key"

# Create multiple Anthropic targets for different models
gibson target add claude-opus-prod --provider anthropic --model claude-3-opus-20240229 --credential anthropic-enterprise
gibson target add claude-sonnet-dev --provider anthropic --model claude-3-sonnet-20240229 --credential anthropic-enterprise
gibson target add claude-haiku-quick --provider anthropic --model claude-3-haiku-20240307 --credential anthropic-enterprise

# Test enterprise targets
gibson target test claude-opus-prod claude-sonnet-dev claude-haiku-quick
```

#### Multi-Provider Testing Setup
```bash
# Set up multiple providers for comprehensive testing
gibson target add anthropic-test --provider anthropic --credential anthropic-key
gibson target add openai-test --provider openai --credential openai-key
gibson target add cohere-test --provider cohere --credential cohere-key
gibson target add huggingface-test --provider huggingface --credential hf-key

# Run cross-provider security tests
gibson scan start --targets anthropic-test,openai-test,cohere-test --payload-category model
```

### Best Practices

1. **Use Descriptive Names**: Choose clear target names that indicate provider and purpose
2. **Organize by Environment**: Use suffixes like `-prod`, `-dev`, `-test`
3. **Secure Credential Storage**: Always use credential references rather than direct API keys
4. **Test Before Use**: Always test targets after creation
5. **Monitor Usage**: Regularly check target health and credential validity
6. **Update Regularly**: Keep credentials current and remove unused targets