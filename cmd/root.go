// SPDX-License-Identifier: MIT
// Copyright Authors of Gibson

package cmd

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"time"

	"github.com/gibson-sec/gibson-framework-2/internal/config"
	"github.com/lmittmann/tint"
	"github.com/mattn/go-colorable"
	"github.com/spf13/cobra"
)

const (
	appName      = config.AppName
	shortAppDesc = "A graphical CLI for AI/ML security testing and assessment."
	longAppDesc  = "Gibson is a CLI to view and manage AI/ML security testing workflows."
)

var (
	version, commit, date = "dev", "dev", "N/A"
	gibsonFlags          *config.Flags

	rootCmd = &cobra.Command{
		Use:   appName,
		Short: shortAppDesc,
		Long:  longAppDesc,
		RunE:  run,
	}

	out = colorable.NewColorableStdout()
)

type flagError struct{ err error }

func (e flagError) Error() string { return e.err.Error() }

func init() {
	// Set up flag error handling
	rootCmd.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return flagError{err: err}
	})

	// Add subcommands
	rootCmd.AddCommand(initCmd(), versionCmd(), scanCmd(), targetCmd(), pluginCmd(), statusCmd(), credentialCmd(), reportCmd(), payloadCmd(), consoleCmd(), helpCmd())

	// Initialize flags
	initGibsonFlags()
}

// Execute root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		if !errors.As(err, &flagError{}) {
			slog.Error("Command execution failed", "error", err)
			os.Exit(1)
		}
	}
}

func run(*cobra.Command, []string) error {
	// Initialize log directories
	if err := initLogDirs(); err != nil {
		return err
	}

	// Set up log file
	logFile, err := os.OpenFile(
		*gibsonFlags.LogFile,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return fmt.Errorf("log file %q init failed: %w", *gibsonFlags.LogFile, err)
	}
	defer func() {
		if logFile != nil {
			_ = logFile.Close()
		}
	}()

	// Set up panic recovery
	defer func() {
		if err := recover(); err != nil {
			slog.Error("Boom!! Gibson init failed", "error", err)
			slog.Error("Stack trace", "stack", string(debug.Stack()))
			fmt.Printf("Boom!! Gibson initialization failed: %v\n", err)
		}
	}()

	// Set up structured logging
	slog.SetDefault(slog.New(tint.NewHandler(logFile, &tint.Options{
		Level:      parseLevel(*gibsonFlags.LogLevel),
		TimeFormat: time.RFC3339,
	})))

	// Operation completed - silent logging

	// Load configuration
	cfg, err := loadConfiguration()
	if err != nil {
		slog.Warn("Failed to load configuration", "error", err)
		return err
	}

	// For now, just show that we're running
	fmt.Printf("Gibson v%s (commit: %s, date: %s)\n", version, commit, date)
	fmt.Printf("Configuration loaded successfully: %+v\n", cfg)
	fmt.Println("Gibson is ready for AI/ML security testing!")
	fmt.Println("Use --help to see available commands and options.")

	return nil
}

func loadConfiguration() (map[string]interface{}, error) {
	// Placeholder configuration loading
	// This will be implemented properly when we port the config system
	config := map[string]interface{}{
		"app_name":    appName,
		"version":     version,
		"log_level":   *gibsonFlags.LogLevel,
		"log_file":    *gibsonFlags.LogFile,
		"read_only":   *gibsonFlags.ReadOnly,
		"headless":    *gibsonFlags.Headless,
	}

	return config, nil
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func initLogDirs() error {
	// Create log directory if it doesn't exist
	logDir := "/tmp"
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}
	}
	return nil
}

func initGibsonFlags() {
	gibsonFlags = config.NewFlags()

	rootCmd.Flags().Float32VarP(
		gibsonFlags.RefreshRate,
		"refresh", "r",
		config.DefaultRefreshRate,
		"Specify the default refresh rate as a float (sec)",
	)
	rootCmd.Flags().StringVarP(
		gibsonFlags.LogLevel,
		"logLevel", "l",
		config.DefaultLogLevel,
		"Specify a log level (error, warn, info, debug)",
	)
	rootCmd.Flags().StringVarP(
		gibsonFlags.LogFile,
		"logFile", "",
		config.AppLogFile,
		"Specify the log file",
	)
	rootCmd.Flags().BoolVar(
		gibsonFlags.Headless,
		"headless",
		false,
		"Turn Gibson header off",
	)
	rootCmd.Flags().BoolVar(
		gibsonFlags.Logoless,
		"logoless",
		false,
		"Turn Gibson logo off",
	)
	rootCmd.Flags().BoolVar(
		gibsonFlags.Crumbsless,
		"crumbsless",
		false,
		"Turn Gibson breadcrumbs off",
	)
	rootCmd.Flags().BoolVar(
		gibsonFlags.Splashless,
		"splashless",
		false,
		"Turn Gibson splash screen off",
	)
	rootCmd.Flags().BoolVarP(
		gibsonFlags.AllTargets,
		"all-targets", "A",
		false,
		"Launch Gibson with all targets",
	)
	rootCmd.Flags().StringVarP(
		gibsonFlags.Command,
		"command", "c",
		config.DefaultCommand,
		"Overrides the default resource to load when the application launches",
	)
	rootCmd.Flags().BoolVar(
		gibsonFlags.ReadOnly,
		"readonly",
		false,
		"Sets readOnly mode by overriding readOnly configuration setting",
	)
	rootCmd.Flags().BoolVar(
		gibsonFlags.Write,
		"write",
		false,
		"Sets write mode by overriding the readOnly configuration setting",
	)
	rootCmd.Flags().StringVar(
		gibsonFlags.ScreenDumpDir,
		"screen-dump-dir",
		"",
		"Sets a path to a dir for screen dumps",
	)
	rootCmd.Flags().StringVarP(
		gibsonFlags.ConfigFile,
		"config", "",
		"",
		"Path to the configuration file to use for Gibson",
	)
}