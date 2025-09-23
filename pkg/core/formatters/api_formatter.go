// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package formatters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	coremodels "github.com/gibson-sec/gibson-framework-2/pkg/core/models"
)

// APIFormatter formats payloads into API requests based on domain
type APIFormatter struct{}

// APIRequest represents a formatted API request
type APIRequest struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string]string   `json:"headers"`
	Body    interface{}         `json:"body"`
	Timeout int                 `json:"timeout_seconds"`
}

// TargetConfig represents target configuration for API requests
type TargetConfig struct {
	Name     string            `json:"name"`
	URL      string            `json:"url"`
	Provider string            `json:"provider"`
	Model    string            `json:"model,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	APIKey   string            `json:"api_key,omitempty"`
}

// ChatMessage represents a chat API message
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest represents a chat API request body
type ChatRequest struct {
	Model       string        `json:"model"`
	Messages    []ChatMessage `json:"messages"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	Temperature float64       `json:"temperature,omitempty"`
	Stream      bool          `json:"stream,omitempty"`
}

// DataRequest represents a data domain API request body
type DataRequest struct {
	Input   string      `json:"input"`
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

// SystemRequest represents a system/infrastructure domain request
type SystemRequest struct {
	Command   string                 `json:"command"`
	Arguments []string               `json:"arguments,omitempty"`
	Config    map[string]interface{} `json:"config,omitempty"`
}

// NewAPIFormatter creates a new API formatter instance
func NewAPIFormatter() *APIFormatter {
	return &APIFormatter{}
}

// FormatRequest formats a payload into an appropriate API request based on domain
// Implements requirement 6: domain-specific API request formatting
func (f *APIFormatter) FormatRequest(payload *coremodels.PayloadDB, target TargetConfig) (*APIRequest, error) {
	if payload == nil {
		return nil, fmt.Errorf("payload cannot be nil")
	}

	if target.URL == "" {
		return nil, fmt.Errorf("target URL is required")
	}

	switch strings.ToLower(payload.Domain) {
	case "model", "interface":
		return f.formatChatRequest(payload, target)
	case "data":
		return f.formatDataRequest(payload, target)
	case "infrastructure", "system":
		return f.formatSystemRequest(payload, target)
	case "output":
		return f.formatOutputRequest(payload, target)
	case "process":
		return f.formatProcessRequest(payload, target)
	default:
		return f.formatGenericRequest(payload, target)
	}
}

// formatChatRequest formats payload as chat messages for model/interface domains
func (f *APIFormatter) formatChatRequest(payload *coremodels.PayloadDB, target TargetConfig) (*APIRequest, error) {
	// Create chat request based on provider
	var body interface{}
	var headers map[string]string

	switch strings.ToLower(target.Provider) {
	case "anthropic":
		body = map[string]interface{}{
			"model":      f.getModel(target),
			"max_tokens": 1024,
			"messages": []ChatMessage{
				{
					Role:    "user",
					Content: payload.Content,
				},
			},
		}
		headers = map[string]string{
			"Content-Type":      "application/json",
			"x-api-key":         target.APIKey,
			"anthropic-version": "2023-06-01",
		}

	case "openai":
		body = ChatRequest{
			Model: f.getModel(target),
			Messages: []ChatMessage{
				{
					Role:    "user",
					Content: payload.Content,
				},
			},
			MaxTokens:   1024,
			Temperature: 0.7,
			Stream:      false,
		}
		headers = map[string]string{
			"Content-Type":  "application/json",
			"Authorization": fmt.Sprintf("Bearer %s", target.APIKey),
		}

	default:
		// Generic chat format
		body = ChatRequest{
			Model: f.getModel(target),
			Messages: []ChatMessage{
				{
					Role:    "user",
					Content: payload.Content,
				},
			},
		}
		headers = map[string]string{
			"Content-Type": "application/json",
		}
	}

	// Merge with target-specific headers
	if target.Headers != nil {
		for k, v := range target.Headers {
			headers[k] = v
		}
	}

	return &APIRequest{
		Method:  "POST",
		URL:     target.URL,
		Headers: headers,
		Body:    body,
		Timeout: 30,
	}, nil
}

// formatDataRequest formats payload for data domain
func (f *APIFormatter) formatDataRequest(payload *coremodels.PayloadDB, target TargetConfig) (*APIRequest, error) {
	body := DataRequest{
		Input:   payload.Content,
		Type:    string(payload.Type),
		Payload: payload.Content,
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	if target.APIKey != "" {
		headers["Authorization"] = fmt.Sprintf("Bearer %s", target.APIKey)
	}

	// Merge with target-specific headers
	if target.Headers != nil {
		for k, v := range target.Headers {
			headers[k] = v
		}
	}

	return &APIRequest{
		Method:  "POST",
		URL:     target.URL,
		Headers: headers,
		Body:    body,
		Timeout: 60,
	}, nil
}

// formatSystemRequest formats payload for infrastructure/system domain
func (f *APIFormatter) formatSystemRequest(payload *coremodels.PayloadDB, target TargetConfig) (*APIRequest, error) {
	body := SystemRequest{
		Command: payload.Content,
		Config:  payload.Config,
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	if target.APIKey != "" {
		headers["Authorization"] = fmt.Sprintf("Bearer %s", target.APIKey)
	}

	// Merge with target-specific headers
	if target.Headers != nil {
		for k, v := range target.Headers {
			headers[k] = v
		}
	}

	return &APIRequest{
		Method:  "POST",
		URL:     target.URL,
		Headers: headers,
		Body:    body,
		Timeout: 120,
	}, nil
}

// formatOutputRequest formats payload for output domain
func (f *APIFormatter) formatOutputRequest(payload *coremodels.PayloadDB, target TargetConfig) (*APIRequest, error) {
	body := map[string]interface{}{
		"output_type": string(payload.Type),
		"content":     payload.Content,
		"config":      payload.Config,
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	if target.APIKey != "" {
		headers["Authorization"] = fmt.Sprintf("Bearer %s", target.APIKey)
	}

	// Merge with target-specific headers
	if target.Headers != nil {
		for k, v := range target.Headers {
			headers[k] = v
		}
	}

	return &APIRequest{
		Method:  "POST",
		URL:     target.URL,
		Headers: headers,
		Body:    body,
		Timeout: 45,
	}, nil
}

// formatProcessRequest formats payload for process domain
func (f *APIFormatter) formatProcessRequest(payload *coremodels.PayloadDB, target TargetConfig) (*APIRequest, error) {
	body := map[string]interface{}{
		"process_type": string(payload.Type),
		"payload":      payload.Content,
		"variables":    payload.Variables,
		"config":       payload.Config,
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	if target.APIKey != "" {
		headers["Authorization"] = fmt.Sprintf("Bearer %s", target.APIKey)
	}

	// Merge with target-specific headers
	if target.Headers != nil {
		for k, v := range target.Headers {
			headers[k] = v
		}
	}

	return &APIRequest{
		Method:  "POST",
		URL:     target.URL,
		Headers: headers,
		Body:    body,
		Timeout: 90,
	}, nil
}

// formatGenericRequest formats payload as generic API request
func (f *APIFormatter) formatGenericRequest(payload *coremodels.PayloadDB, target TargetConfig) (*APIRequest, error) {
	body := map[string]interface{}{
		"content":    payload.Content,
		"type":       string(payload.Type),
		"domain":     payload.Domain,
		"variables":  payload.Variables,
		"config":     payload.Config,
	}

	headers := map[string]string{
		"Content-Type": "application/json",
	}

	if target.APIKey != "" {
		headers["Authorization"] = fmt.Sprintf("Bearer %s", target.APIKey)
	}

	// Merge with target-specific headers
	if target.Headers != nil {
		for k, v := range target.Headers {
			headers[k] = v
		}
	}

	return &APIRequest{
		Method:  "POST",
		URL:     target.URL,
		Headers: headers,
		Body:    body,
		Timeout: 30,
	}, nil
}

// CreateHTTPRequest converts APIRequest to http.Request
func (f *APIFormatter) CreateHTTPRequest(apiReq *APIRequest) (*http.Request, error) {
	if apiReq == nil {
		return nil, fmt.Errorf("api request cannot be nil")
	}

	var body []byte
	var err error

	if apiReq.Body != nil {
		body, err = json.Marshal(apiReq.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
	}

	req, err := http.NewRequest(apiReq.Method, apiReq.URL, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	for key, value := range apiReq.Headers {
		req.Header.Set(key, value)
	}

	return req, nil
}

// getModel returns the model name, defaulting if not specified
func (f *APIFormatter) getModel(target TargetConfig) string {
	if target.Model != "" {
		return target.Model
	}

	// Default models by provider
	switch strings.ToLower(target.Provider) {
	case "anthropic":
		return "claude-3-haiku-20240307"
	case "openai":
		return "gpt-3.5-turbo"
	default:
		return "default"
	}
}

// ValidateAPIRequest validates an API request structure
func (f *APIFormatter) ValidateAPIRequest(apiReq *APIRequest) error {
	if apiReq == nil {
		return fmt.Errorf("api request cannot be nil")
	}

	if apiReq.Method == "" {
		return fmt.Errorf("HTTP method is required")
	}

	if apiReq.URL == "" {
		return fmt.Errorf("URL is required")
	}

	if apiReq.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive")
	}

	return nil
}