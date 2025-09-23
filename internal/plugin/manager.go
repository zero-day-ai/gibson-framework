package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/hashicorp/go-hclog"
	sdkplugin "github.com/zero-day-ai/gibson-sdk/pkg/plugin"
	"github.com/zero-day-ai/gibson-sdk/pkg/grpc"
)

// Manager handles plugin discovery, loading, and lifecycle management
type Manager struct {
	logger       *slog.Logger
	pluginDir    string
	plugins      map[string]*PluginInstance
	mutex        sync.RWMutex
	useGRPC      bool
	maxPlugins   int
	pluginTimeout time.Duration
}

// PluginInstance represents a loaded plugin instance
type PluginInstance struct {
	Name        string
	Path        string
	Client      *plugin.Client
	Plugin      sdkplugin.SecurityPlugin
	Config      *PluginConfig
	LastUsed    time.Time
	UseCount    int64
	Health      HealthStatus
	mu          sync.RWMutex
}

// PluginConfig contains plugin configuration loaded from manifest
type PluginConfig struct {
	Name         string                 `yaml:"name" json:"name"`
	Version      string                 `yaml:"version" json:"version"`
	Description  string                 `yaml:"description" json:"description"`
	Author       string                 `yaml:"author" json:"author"`
	Executable   string                 `yaml:"executable" json:"executable"`
	Args         []string               `yaml:"args" json:"args"`
	Env          map[string]string      `yaml:"env" json:"env"`
	Timeout      time.Duration          `yaml:"timeout" json:"timeout"`
	MaxMemory    int64                  `yaml:"max_memory" json:"max_memory"`
	Domains      []sdkplugin.SecurityDomain `yaml:"domains" json:"domains"`
	Capabilities []string               `yaml:"capabilities" json:"capabilities"`
	Config       map[string]interface{} `yaml:"config" json:"config"`
}

// HealthStatus represents plugin health state
type HealthStatus string

const (
	HealthUnknown   HealthStatus = "unknown"
	HealthHealthy   HealthStatus = "healthy"
	HealthUnhealthy HealthStatus = "unhealthy"
	HealthCrashed   HealthStatus = "crashed"
	HealthDisabled  HealthStatus = "disabled"
)

// ManagerOption configures the plugin manager
type ManagerOption func(*Manager)

// WithLogger sets the logger for the plugin manager
func WithLogger(logger *slog.Logger) ManagerOption {
	return func(m *Manager) {
		m.logger = logger
	}
}

// WithGRPC enables gRPC communication for plugins
func WithGRPC(useGRPC bool) ManagerOption {
	return func(m *Manager) {
		m.useGRPC = useGRPC
	}
}

// WithMaxPlugins sets the maximum number of concurrent plugins
func WithMaxPlugins(max int) ManagerOption {
	return func(m *Manager) {
		m.maxPlugins = max
	}
}

// WithTimeout sets the default plugin timeout
func WithTimeout(timeout time.Duration) ManagerOption {
	return func(m *Manager) {
		m.pluginTimeout = timeout
	}
}

// NewManager creates a new plugin manager
func NewManager(pluginDir string, opts ...ManagerOption) *Manager {
	m := &Manager{
		logger:        slog.Default(),
		pluginDir:     pluginDir,
		plugins:       make(map[string]*PluginInstance),
		useGRPC:       true,  // Default to gRPC for better performance
		maxPlugins:    10,    // Default max concurrent plugins
		pluginTimeout: 30 * time.Second,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Discover scans the plugin directory for available plugins
func (m *Manager) Discover() ([]string, error) {
	m.logger.Debug("discovering plugins", "dir", m.pluginDir)

	if _, err := os.Stat(m.pluginDir); os.IsNotExist(err) {
		m.logger.Warn("plugin directory does not exist", "dir", m.pluginDir)
		return nil, nil
	}

	var plugins []string
	err := filepath.Walk(m.pluginDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Look for plugin manifest files
		if info.Name() == "plugin.yml" || info.Name() == "plugin.yaml" {
			pluginName := filepath.Base(filepath.Dir(path))
			plugins = append(plugins, pluginName)
			m.logger.Debug("discovered plugin", "name", pluginName, "path", path)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error discovering plugins: %w", err)
	}

	m.logger.Info("plugin discovery completed", "count", len(plugins))
	return plugins, nil
}

// Load loads a plugin by name
func (m *Manager) Load(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if already loaded
	if _, exists := m.plugins[name]; exists {
		return nil
	}

	// Check max plugins limit
	if len(m.plugins) >= m.maxPlugins {
		return fmt.Errorf("maximum plugin limit reached (%d)", m.maxPlugins)
	}

	m.logger.Debug("loading plugin", "name", name)

	// Load plugin configuration
	config, err := m.loadConfig(name)
	if err != nil {
		return fmt.Errorf("failed to load plugin config: %w", err)
	}

	// Find executable
	execPath := filepath.Join(m.pluginDir, name, config.Executable)
	if _, err := os.Stat(execPath); os.IsNotExist(err) {
		return fmt.Errorf("plugin executable not found: %s", execPath)
	}

	// Create plugin client
	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig:  grpc.HandshakeConfig,
		Plugins:          m.getPluginMap(),
		Cmd:              exec.Command(execPath, config.Args...),
		AllowedProtocols: m.getAllowedProtocols(),
		Logger:           m.createHCLogger(),
		Stderr:           os.Stderr,
	})

	// Connect to plugin
	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return fmt.Errorf("failed to connect to plugin: %w", err)
	}

	// Get plugin interface
	raw, err := rpcClient.Dispense("security")
	if err != nil {
		client.Kill()
		return fmt.Errorf("failed to dispense plugin: %w", err)
	}

	securityPlugin, ok := raw.(sdkplugin.SecurityPlugin)
	if !ok {
		client.Kill()
		return fmt.Errorf("plugin does not implement SecurityPlugin interface")
	}

	// Test plugin health by getting plugin info (new SDK doesn't have Health method)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	infoResult := securityPlugin.GetInfo(ctx)
	if infoResult.IsErr() {
		client.Kill()
		return fmt.Errorf("plugin health check failed: %w", infoResult.Error())
	}

	// Create plugin instance
	instance := &PluginInstance{
		Name:     name,
		Path:     execPath,
		Client:   client,
		Plugin:   securityPlugin,
		Config:   config,
		LastUsed: time.Now(),
		UseCount: 0,
		Health:   HealthHealthy,
	}

	m.plugins[name] = instance
	m.logger.Info("plugin loaded successfully", "name", name)

	return nil
}

// Get retrieves a loaded plugin by name
func (m *Manager) Get(name string) (*PluginInstance, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	instance, exists := m.plugins[name]
	if !exists {
		return nil, fmt.Errorf("plugin not loaded: %s", name)
	}

	// Update usage statistics
	instance.mu.Lock()
	instance.LastUsed = time.Now()
	instance.UseCount++
	instance.mu.Unlock()

	return instance, nil
}

// Unload unloads a plugin and cleans up resources
func (m *Manager) Unload(name string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	instance, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("plugin not loaded: %s", name)
	}

	m.logger.Debug("unloading plugin", "name", name)

	// Kill the plugin client
	instance.Client.Kill()

	// Remove from plugins map
	delete(m.plugins, name)

	m.logger.Info("plugin unloaded", "name", name)
	return nil
}

// List returns a list of all loaded plugins
func (m *Manager) List() []*PluginInstance {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	instances := make([]*PluginInstance, 0, len(m.plugins))
	for _, instance := range m.plugins {
		instances = append(instances, instance)
	}

	return instances
}

// Reload reloads a plugin (unload then load)
func (m *Manager) Reload(name string) error {
	if err := m.Unload(name); err != nil {
		// Don't fail if plugin wasn't loaded
		m.logger.Warn("failed to unload plugin during reload", "name", name, "error", err)
	}

	return m.Load(name)
}

// Shutdown gracefully shuts down all plugins
func (m *Manager) Shutdown() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Info("shutting down plugin manager", "count", len(m.plugins))

	for name, instance := range m.plugins {
		m.logger.Debug("shutting down plugin", "name", name)
		instance.Client.Kill()
	}

	m.plugins = make(map[string]*PluginInstance)
}

// HealthCheck performs health checks on all loaded plugins
func (m *Manager) HealthCheck() map[string]HealthStatus {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	results := make(map[string]HealthStatus)

	for name, instance := range m.plugins {
		// Check health by calling GetInfo (SDK doesn't have dedicated Health method)
		ctx := context.Background()
		infoResult := instance.Plugin.GetInfo(ctx)
		if infoResult.IsErr() {
			instance.mu.Lock()
			instance.Health = HealthUnhealthy
			instance.mu.Unlock()
			results[name] = HealthUnhealthy
		} else {
			instance.mu.Lock()
			instance.Health = HealthHealthy
			instance.mu.Unlock()
			results[name] = HealthHealthy
		}
	}

	return results
}

// loadConfig loads plugin configuration from manifest file
func (m *Manager) loadConfig(name string) (*PluginConfig, error) {
	// Implementation would load from plugin.yml in the plugin directory
	// For now, return a basic config
	return &PluginConfig{
		Name:        name,
		Version:     "1.0.0",
		Description: "Security plugin",
		Author:      "Gibson Framework",
		Executable:  name,
		Args:        []string{},
		Env:         make(map[string]string),
		Timeout:     m.pluginTimeout,
		MaxMemory:   512 * 1024 * 1024, // 512MB default
		Domains:     []sdkplugin.SecurityDomain{sdkplugin.DomainInterface},
		Capabilities: []string{"assess"},
		Config:      make(map[string]interface{}),
	}, nil
}

// getAllowedProtocols returns the allowed plugin protocols
func (m *Manager) getAllowedProtocols() []plugin.Protocol {
	if m.useGRPC {
		return []plugin.Protocol{plugin.ProtocolGRPC, plugin.ProtocolNetRPC}
	}
	return []plugin.Protocol{plugin.ProtocolNetRPC}
}

// getPluginMap returns the plugin map for the specified protocol
func (m *Manager) getPluginMap() map[string]plugin.Plugin {
	return map[string]plugin.Plugin{
		"security": &grpc.GibsonSecurityPlugin{},
	}
}

// createHCLogger creates a logger compatible with HashiCorp go-plugin
func (m *Manager) createHCLogger() hclog.Logger {
	// Return a simple logger that wraps our slog logger
	return hclog.New(&hclog.LoggerOptions{
		Name:   "plugin-manager",
		Level:  hclog.Debug,
		Output: os.Stderr,
	})
}