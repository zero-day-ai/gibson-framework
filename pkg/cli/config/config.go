// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Gibson

package config

import (
	"strings"

	"github.com/spf13/viper"
)

// Config represents the complete application configuration
type Config struct {
	// Core application settings
	LogLevel    string `mapstructure:"log_level"`
	LogFile     string `mapstructure:"log_file"`
	DatabaseURL string `mapstructure:"database_url"`

	// Model defaulting configuration
	ModelDefaults ProviderModelDefaults `mapstructure:"model_defaults"`

	// Server configuration
	Server ServerConfig `mapstructure:"server"`
}

// ProviderModelDefaults represents default model configuration for each provider
type ProviderModelDefaults struct {
	AnthropicDefault string `mapstructure:"anthropic_default"`
	OpenAIDefault    string `mapstructure:"openai_default"`
	GoogleDefault    string `mapstructure:"google_default"`
	CohereDefault    string `mapstructure:"cohere_default"`
	CacheTTLHours    int    `mapstructure:"cache_ttl_hours"`
}

// ServerConfig represents server-specific configuration
type ServerConfig struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		LogLevel:    "info",
		LogFile:     "/tmp/gibson.log",
		DatabaseURL: "sqlite:///tmp/gibson.db",
		ModelDefaults: ProviderModelDefaults{
			AnthropicDefault: "claude-3-5-sonnet-20241022",
			OpenAIDefault:    "gpt-4-turbo-preview",
			GoogleDefault:    "gemini-1.5-pro",
			CohereDefault:    "command-r-plus",
			CacheTTLHours:    24,
		},
		Server: ServerConfig{
			Host: "localhost",
			Port: 8080,
		},
	}
}

// LoadConfig loads configuration from files and environment variables using viper
func LoadConfig() (*Config, error) {
	// Set up viper configuration
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("$HOME/.gibson")
	viper.AddConfigPath(".")

	// Environment variable overrides
	viper.SetEnvPrefix("GIBSON")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set default values
	setDefaults()

	// Read configuration file
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
		// Config file not found is OK, we'll use defaults
	}

	// Unmarshal into Config struct
	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

// setDefaults sets default values in viper
func setDefaults() {
	viper.SetDefault("log_level", "info")
	viper.SetDefault("log_file", "/tmp/gibson.log")
	viper.SetDefault("database_url", "sqlite:///tmp/gibson.db")

	// Model defaults
	viper.SetDefault("model_defaults.anthropic_default", "claude-3-5-sonnet-20241022")
	viper.SetDefault("model_defaults.openai_default", "gpt-4-turbo-preview")
	viper.SetDefault("model_defaults.google_default", "gemini-1.5-pro")
	viper.SetDefault("model_defaults.cohere_default", "command-r-plus")
	viper.SetDefault("model_defaults.cache_ttl_hours", 24)

	// Server defaults
	viper.SetDefault("server.host", "localhost")
	viper.SetDefault("server.port", 8080)
}

// GetString returns a string configuration value
func GetString(key string) string {
	return viper.GetString(key)
}

// GetInt returns an integer configuration value
func GetInt(key string) int {
	return viper.GetInt(key)
}

// GetBool returns a boolean configuration value
func GetBool(key string) bool {
	return viper.GetBool(key)
}

// Set sets a configuration value
func Set(key string, value interface{}) {
	viper.Set(key, value)
}

// GetProviderModelDefaults returns the current model defaults configuration
func GetProviderModelDefaults() ProviderModelDefaults {
	return ProviderModelDefaults{
		AnthropicDefault: viper.GetString("model_defaults.anthropic_default"),
		OpenAIDefault:    viper.GetString("model_defaults.openai_default"),
		GoogleDefault:    viper.GetString("model_defaults.google_default"),
		CohereDefault:    viper.GetString("model_defaults.cohere_default"),
		CacheTTLHours:    viper.GetInt("model_defaults.cache_ttl_hours"),
	}
}

// SetProviderModelDefault sets a default model for a specific provider
func SetProviderModelDefault(provider, model string) {
	key := "model_defaults." + strings.ToLower(provider) + "_default"
	viper.Set(key, model)
}

// GetProviderModelDefault gets the default model for a specific provider
func GetProviderModelDefault(provider string) string {
	key := "model_defaults." + strings.ToLower(provider) + "_default"
	return viper.GetString(key)
}