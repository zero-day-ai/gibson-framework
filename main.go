// SPDX-License-Identifier: MIT
// Copyright Authors of Gibson

package main

import (
	"flag"
	"log/slog"

	"github.com/gibson-sec/gibson-framework-2/cmd"
)

func init() {
	// Initialize slog with reasonable defaults
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	handler := slog.NewTextHandler(flag.CommandLine.Output(), opts)
	slog.SetDefault(slog.New(handler))
}

func main() {
	cmd.Execute()
}