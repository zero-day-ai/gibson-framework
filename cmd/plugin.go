// SPDX-License-Identifier: MIT
// Copyright Authors of Gibson

package cmd

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson-framework/internal/view"
	"github.com/spf13/cobra"
)

var (
	pluginNameFlag   *string
	pluginPathFlag   *string
	pluginConfigFlag *string
	pluginOutputFlag *string
	pluginIDFlag     *string
	pluginTypeFlag   *string
)

// pluginCmd creates the plugin command following k9s patterns
func pluginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "plugin",
		Aliases: []string{"p", "plugins"},
		Short:   "Manage security plugins",
		Long:    "List, enable, disable, and manage security testing plugins",
	}

	// Add subcommands
	cmd.AddCommand(
		pluginListCmd(),
		pluginEnableCmd(),
		pluginDisableCmd(),
		pluginInfoCmd(),
		pluginInstallCmd(),
		pluginUninstallCmd(),
		pluginUpdateCmd(),
		pluginStatusCmd(),
		pluginDiscoverCmd(),
		pluginValidateCmd(),
		pluginStatsCmd(),
	)

	return cmd
}

// pluginListCmd lists available plugins
func pluginListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls", "get"},
		Short:   "List security plugins",
		Long:    "List all available security testing plugins with their status and information",
		RunE:    runPluginList,
		Example: `  # List all plugins
  gibson plugin list

  # List plugins in JSON format
  gibson plugin list --output json

  # List only enabled plugins
  gibson plugin list --status enabled

  # List plugins by type
  gibson plugin list --type injection`,
	}

	pluginOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().String("status", "", "Filter by status (enabled, disabled, error)")
	cmd.Flags().String("type", "", "Filter by plugin type (injection, model, infrastructure)")

	return cmd
}

// pluginEnableCmd enables plugins
func pluginEnableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "enable [NAME]",
		Aliases: []string{"activate", "on"},
		Short:   "Enable security plugins",
		Long:    "Enable one or more security testing plugins for use in scans",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runPluginEnable,
		Example: `  # Enable a specific plugin
  gibson plugin enable sql-injection

  # Enable plugin by ID
  gibson plugin enable --id plugin-123

  # Enable all plugins of a type
  gibson plugin enable --type injection

  # Enable all disabled plugins
  gibson plugin enable --all`,
	}

	pluginNameFlag = cmd.Flags().StringP("name", "n", "", "Plugin name (if not provided as argument)")
	pluginIDFlag = cmd.Flags().String("id", "", "Plugin ID to enable")
	pluginTypeFlag = cmd.Flags().String("type", "", "Enable all plugins of this type")
	cmd.Flags().BoolP("all", "a", false, "Enable all disabled plugins")
	pluginOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// pluginDisableCmd disables plugins
func pluginDisableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "disable [NAME]",
		Aliases: []string{"deactivate", "off"},
		Short:   "Disable security plugins",
		Long:    "Disable one or more security testing plugins to prevent their use in scans",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runPluginDisable,
		Example: `  # Disable a specific plugin
  gibson plugin disable sql-injection

  # Disable plugin by ID
  gibson plugin disable --id plugin-123

  # Disable all plugins of a type
  gibson plugin disable --type infrastructure

  # Disable all plugins
  gibson plugin disable --all`,
	}

	pluginNameFlag = cmd.Flags().StringP("name", "n", "", "Plugin name (if not provided as argument)")
	pluginIDFlag = cmd.Flags().String("id", "", "Plugin ID to disable")
	pluginTypeFlag = cmd.Flags().String("type", "", "Disable all plugins of this type")
	cmd.Flags().BoolP("all", "a", false, "Disable all enabled plugins")
	pluginOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// pluginInfoCmd shows detailed plugin information
func pluginInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "info [NAME]",
		Aliases: []string{"describe", "show"},
		Short:   "Show detailed plugin information",
		Long:    "Show detailed information about a specific security testing plugin",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runPluginInfo,
		Example: `  # Show plugin information
  gibson plugin info sql-injection

  # Show plugin info by ID
  gibson plugin info --id plugin-123

  # Show info with JSON output
  gibson plugin info sql-injection --output json`,
	}

	pluginNameFlag = cmd.Flags().StringP("name", "n", "", "Plugin name (if not provided as argument)")
	pluginIDFlag = cmd.Flags().String("id", "", "Plugin ID to show info for")
	pluginOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// pluginInstallCmd installs new plugins
func pluginInstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "install [PATH]",
		Aliases: []string{"add", "load"},
		Short:   "Install security plugins",
		Long:    "Install security testing plugins from local files or remote repositories",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runPluginInstall,
		Example: `  # Install plugin from local file
  gibson plugin install ./my-plugin.so

  # Install plugin from path
  gibson plugin install --path /path/to/plugin.so

  # Install plugin with configuration
  gibson plugin install ./my-plugin.so --config ./plugin-config.yaml

  # Install plugin with custom name
  gibson plugin install ./my-plugin.so --name custom-plugin`,
	}

	pluginPathFlag = cmd.Flags().StringP("path", "p", "", "Plugin file path (if not provided as argument)")
	pluginNameFlag = cmd.Flags().StringP("name", "n", "", "Custom plugin name")
	pluginConfigFlag = cmd.Flags().StringP("config", "c", "", "Plugin configuration file")
	pluginOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().BoolP("force", "f", false, "Force installation even if plugin exists")

	return cmd
}

// pluginUninstallCmd uninstalls plugins
func pluginUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "uninstall [NAME]",
		Aliases: []string{"remove", "delete"},
		Short:   "Uninstall security plugins",
		Long:    "Uninstall security testing plugins and remove them from the system",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runPluginUninstall,
		Example: `  # Uninstall a specific plugin
  gibson plugin uninstall my-plugin

  # Uninstall plugin by ID
  gibson plugin uninstall --id plugin-123

  # Force uninstall without confirmation
  gibson plugin uninstall my-plugin --force`,
	}

	pluginNameFlag = cmd.Flags().StringP("name", "n", "", "Plugin name (if not provided as argument)")
	pluginIDFlag = cmd.Flags().String("id", "", "Plugin ID to uninstall")
	cmd.Flags().BoolP("force", "f", false, "Force uninstall without confirmation")
	pluginOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// pluginUpdateCmd updates plugin configuration
func pluginUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "update [NAME]",
		Aliases: []string{"config", "configure"},
		Short:   "Update plugin configuration",
		Long:    "Update configuration for security testing plugins",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runPluginUpdate,
		Example: `  # Update plugin configuration
  gibson plugin update my-plugin --config ./new-config.yaml

  # Update plugin by ID
  gibson plugin update --id plugin-123 --config ./config.yaml`,
	}

	pluginNameFlag = cmd.Flags().StringP("name", "n", "", "Plugin name (if not provided as argument)")
	pluginIDFlag = cmd.Flags().String("id", "", "Plugin ID to update")
	pluginConfigFlag = cmd.Flags().StringP("config", "c", "", "New configuration file")
	pluginOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")

	return cmd
}

// pluginStatusCmd shows plugin health status
func pluginStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "status [NAME]",
		Aliases: []string{"health", "check"},
		Short:   "Show plugin health status",
		Long:    "Show health status, resource usage, and error rates for security testing plugins",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runPluginStatus,
		Example: `  # Show status of all plugins
  gibson plugin status

  # Show status of specific plugin
  gibson plugin status sql-injection

  # Show status by plugin ID
  gibson plugin status --id plugin-123

  # Show status in JSON format
  gibson plugin status --output json`,
	}

	pluginNameFlag = cmd.Flags().StringP("name", "n", "", "Plugin name (if not provided as argument)")
	pluginIDFlag = cmd.Flags().String("id", "", "Plugin ID to check status for")
	pluginOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().BoolP("watch", "w", false, "Watch plugin status continuously")

	return cmd
}

// pluginDiscoverCmd discovers new plugins
func pluginDiscoverCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "discover [PATH]",
		Aliases: []string{"scan", "find"},
		Short:   "Discover new plugins",
		Long:    "Scan plugin directories and discover new security testing plugins",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runPluginDiscover,
		Example: `  # Discover plugins in default directories
  gibson plugin discover

  # Discover plugins in specific path
  gibson plugin discover /path/to/plugins

  # Discover and auto-register new plugins
  gibson plugin discover --auto-register

  # Discover with recursive scan
  gibson plugin discover --recursive /path/to/plugins`,
	}

	pluginPathFlag = cmd.Flags().StringP("path", "p", "", "Plugin directory path (if not provided as argument)")
	pluginOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().BoolP("auto-register", "a", false, "Automatically register discovered plugins")
	cmd.Flags().BoolP("recursive", "r", false, "Recursively scan subdirectories")

	return cmd
}

// pluginValidateCmd validates plugin integrity
func pluginValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "validate [NAME]",
		Aliases: []string{"verify", "test"},
		Short:   "Validate plugin integrity",
		Long:    "Validate plugin interfaces, verify signatures, and test plugin execution",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runPluginValidate,
		Example: `  # Validate all plugins
  gibson plugin validate

  # Validate specific plugin
  gibson plugin validate sql-injection

  # Validate plugin by ID
  gibson plugin validate --id plugin-123

  # Validate with full test execution
  gibson plugin validate --full-test sql-injection`,
	}

	pluginNameFlag = cmd.Flags().StringP("name", "n", "", "Plugin name (if not provided as argument)")
	pluginIDFlag = cmd.Flags().String("id", "", "Plugin ID to validate")
	pluginOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().BoolP("full-test", "f", false, "Run full test execution validation")
	cmd.Flags().BoolP("signature-check", "s", false, "Verify plugin signatures")

	return cmd
}

// pluginStatsCmd shows plugin usage statistics
func pluginStatsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "stats [NAME]",
		Aliases: []string{"statistics", "metrics"},
		Short:   "Show plugin usage statistics",
		Long:    "Show execution counts, performance metrics, and success rates for security testing plugins",
		Args:    cobra.MaximumNArgs(1),
		RunE:    runPluginStats,
		Example: `  # Show stats for all plugins
  gibson plugin stats

  # Show stats for specific plugin
  gibson plugin stats sql-injection

  # Show stats by plugin ID
  gibson plugin stats --id plugin-123

  # Show detailed performance metrics
  gibson plugin stats --detailed sql-injection`,
	}

	pluginNameFlag = cmd.Flags().StringP("name", "n", "", "Plugin name (if not provided as argument)")
	pluginIDFlag = cmd.Flags().String("id", "", "Plugin ID to show stats for")
	pluginOutputFlag = cmd.Flags().StringP("output", "o", "table", "Output format (table, json, yaml)")
	cmd.Flags().BoolP("detailed", "d", false, "Show detailed performance metrics")
	cmd.Flags().String("period", "24h", "Time period for statistics (1h, 24h, 7d, 30d)")

	return cmd
}

// runPluginList implements the plugin list command
func runPluginList(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create plugin view controller
	pluginView, err := view.NewPluginView()
	if err != nil {
		return fmt.Errorf("failed to create plugin view: %w", err)
	}

	// List plugins through the view layer
	return pluginView.ListPlugins(ctx, view.PluginListOptions{
		Output: getValue(pluginOutputFlag),
	})
}

// runPluginEnable implements the plugin enable command
func runPluginEnable(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create plugin view controller
	pluginView, err := view.NewPluginView()
	if err != nil {
		return fmt.Errorf("failed to create plugin view: %w", err)
	}

	// Enable plugin through the view layer
	return pluginView.EnablePlugin(ctx, view.PluginEnableOptions{
		Name:   getValue(pluginNameFlag),
		ID:     getValue(pluginIDFlag),
		Type:   getValue(pluginTypeFlag),
		Output: getValue(pluginOutputFlag),
	})
}

// runPluginDisable implements the plugin disable command
func runPluginDisable(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create plugin view controller
	pluginView, err := view.NewPluginView()
	if err != nil {
		return fmt.Errorf("failed to create plugin view: %w", err)
	}

	// Disable plugin through the view layer
	return pluginView.DisablePlugin(ctx, view.PluginDisableOptions{
		Name:   getValue(pluginNameFlag),
		ID:     getValue(pluginIDFlag),
		Type:   getValue(pluginTypeFlag),
		Output: getValue(pluginOutputFlag),
	})
}

// runPluginInfo implements the plugin info command
func runPluginInfo(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create plugin view controller
	pluginView, err := view.NewPluginView()
	if err != nil {
		return fmt.Errorf("failed to create plugin view: %w", err)
	}

	// Get plugin info through the view layer
	return pluginView.GetPluginInfo(ctx, view.PluginInfoOptions{
		Name:   getValue(pluginNameFlag),
		ID:     getValue(pluginIDFlag),
		Output: getValue(pluginOutputFlag),
	})
}

// runPluginInstall implements the plugin install command
func runPluginInstall(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create plugin view controller
	pluginView, err := view.NewPluginView()
	if err != nil {
		return fmt.Errorf("failed to create plugin view: %w", err)
	}

	// Install plugin through the view layer
	return pluginView.InstallPlugin(ctx, view.PluginInstallOptions{
		Path:   getValue(pluginPathFlag),
		Name:   getValue(pluginNameFlag),
		Config: getValue(pluginConfigFlag),
		Output: getValue(pluginOutputFlag),
	})
}

// runPluginUninstall implements the plugin uninstall command
func runPluginUninstall(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get plugin name from positional argument or flag
	pluginName, _ := cmd.Flags().GetString("name")
	if len(args) > 0 {
		pluginName = args[0]
	}

	pluginID, _ := cmd.Flags().GetString("id")

	// Validate that we have either name or ID
	if pluginName == "" && pluginID == "" {
		return fmt.Errorf("either plugin name or ID must be specified")
	}

	// Operation completed - silent logging

	// Create plugin view controller
	pluginView, err := view.NewPluginView()
	if err != nil {
		return fmt.Errorf("failed to create plugin view: %w", err)
	}

	// Uninstall plugin through the view layer
	return pluginView.UninstallPlugin(ctx, view.PluginUninstallOptions{
		Name:   pluginName,
		ID:     pluginID,
		Output: getValue(pluginOutputFlag),
	})
}

// runPluginUpdate implements the plugin update command
func runPluginUpdate(*cobra.Command, []string) error {
	ctx := context.Background()
	// Operation completed - silent logging

	// Create plugin view controller
	pluginView, err := view.NewPluginView()
	if err != nil {
		return fmt.Errorf("failed to create plugin view: %w", err)
	}

	// Update plugin through the view layer
	return pluginView.UpdatePlugin(ctx, view.PluginUpdateOptions{
		Name:   getValue(pluginNameFlag),
		ID:     getValue(pluginIDFlag),
		Config: getValue(pluginConfigFlag),
		Output: getValue(pluginOutputFlag),
	})
}

// runPluginStatus implements the plugin status command
func runPluginStatus(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get plugin name from args or flag
	var pluginName string
	if len(args) > 0 {
		pluginName = args[0]
	} else {
		pluginName, _ = cmd.Flags().GetString("name")
	}

	pluginID, _ := cmd.Flags().GetString("id")
	outputFormat, _ := cmd.Flags().GetString("output")

	// Operation completed - silent logging

	// Create plugin view controller
	pluginView, err := view.NewPluginView()
	if err != nil {
		return fmt.Errorf("failed to create plugin view: %w", err)
	}

	// Get plugin status through the view layer
	return pluginView.GetPluginStatus(ctx, view.PluginStatusOptions{
		Name:   pluginName,
		ID:     pluginID,
		Output: outputFormat,
	})
}

// runPluginDiscover implements the plugin discover command
func runPluginDiscover(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get plugin path from args or flag
	var pluginPath string
	if len(args) > 0 {
		pluginPath = args[0]
	} else {
		pluginPath, _ = cmd.Flags().GetString("path")
	}

	outputFormat, _ := cmd.Flags().GetString("output")

	// Operation completed - silent logging

	// Create plugin view controller
	pluginView, err := view.NewPluginView()
	if err != nil {
		return fmt.Errorf("failed to create plugin view: %w", err)
	}

	// Discover plugins through the view layer
	return pluginView.DiscoverPlugins(ctx, view.PluginDiscoverOptions{
		Path:   pluginPath,
		Output: outputFormat,
	})
}

// runPluginValidate implements the plugin validate command
func runPluginValidate(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get plugin name from args or flag
	var pluginName string
	if len(args) > 0 {
		pluginName = args[0]
	} else {
		pluginName, _ = cmd.Flags().GetString("name")
	}

	pluginID, _ := cmd.Flags().GetString("id")
	outputFormat, _ := cmd.Flags().GetString("output")

	// Operation completed - silent logging

	// Create plugin view controller
	pluginView, err := view.NewPluginView()
	if err != nil {
		return fmt.Errorf("failed to create plugin view: %w", err)
	}

	// Validate plugin through the view layer
	return pluginView.ValidatePlugin(ctx, view.PluginValidateOptions{
		Name:   pluginName,
		ID:     pluginID,
		Output: outputFormat,
	})
}

// runPluginStats implements the plugin stats command
func runPluginStats(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Get plugin name from args or flag
	var pluginName string
	if len(args) > 0 {
		pluginName = args[0]
	} else {
		pluginName, _ = cmd.Flags().GetString("name")
	}

	pluginID, _ := cmd.Flags().GetString("id")
	outputFormat, _ := cmd.Flags().GetString("output")

	// Operation completed - silent logging

	// Create plugin view controller
	pluginView, err := view.NewPluginView()
	if err != nil {
		return fmt.Errorf("failed to create plugin view: %w", err)
	}

	// Get plugin stats through the view layer
	return pluginView.GetPluginStats(ctx, view.PluginStatsOptions{
		Name:   pluginName,
		ID:     pluginID,
		Output: outputFormat,
	})
}