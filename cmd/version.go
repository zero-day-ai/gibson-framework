// SPDX-License-Identifier: MIT
// Copyright Authors of Gibson

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func versionCmd() *cobra.Command {
	var short bool

	command := cobra.Command{
		Use:   "version",
		Short: "Print version/build info",
		Long:  "Print version/build information",
		Run: func(*cobra.Command, []string) {
			printVersion(short)
		},
	}

	command.PersistentFlags().BoolVarP(&short, "short", "s", false, "Prints Gibson version info in short format")

	return &command
}

func printVersion(short bool) {
	const fmat = "%-20s %s\n"

	if short {
		fmt.Printf("Gibson %s\n", version)
		return
	}

	printLogo()
	fmt.Printf(fmat, "Version:", version)
	fmt.Printf(fmat, "Commit:", commit)
	fmt.Printf(fmat, "Date:", date)
}

func printLogo() {
	logo := `
   _____ _ _
  / ____(_) |
 | |  __ _| |__  ___  ___  _ __
 | | |_ | | '_ \/ __|/ _ \| '_ \
 | |__| | | |_) \__ \ (_) | | | |
  \_____|_|_.__/|___/\___/|_| |_|

AI/ML Security Testing Framework
`
	fmt.Print(logo)
}