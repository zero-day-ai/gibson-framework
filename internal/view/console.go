// Package view provides console view implementation for interactive REPL
package view

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// consoleView implements an interactive console following k9s patterns
type consoleView struct {
	history     []string
	historyFile string
	commands    map[string]string
}

// ConsoleOptions defines options for the interactive console
type ConsoleOptions struct {
	Prompt    string
	History   bool
	BatchFile string
	Timeout   int
	ReadOnly  bool
}

// NewConsoleView creates a new console view instance
func NewConsoleView() *consoleView {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "/tmp"
	}

	return &consoleView{
		history:     make([]string, 0),
		historyFile: filepath.Join(homeDir, ".gibson_history"),
		commands:    getAvailableCommands(),
	}
}

// StartConsole starts the interactive console
func (cv *consoleView) StartConsole(ctx context.Context, opts ConsoleOptions) error {
	// Operation completed - silent logging

	// Handle batch mode
	if opts.BatchFile != "" {
		return cv.runBatchCommands(ctx, opts)
	}

	// Load command history
	if opts.History {
		if err := cv.loadHistory(); err != nil {
			slog.Warn("Failed to load command history", "error", err)
		}
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Set up timeout if specified
	var timeoutChan <-chan time.Time
	if opts.Timeout > 0 {
		timeoutChan = time.After(time.Duration(opts.Timeout) * time.Second)
	}

	// Print welcome message
	cv.printWelcome(opts)

	// Main console loop
	reader := bufio.NewReader(os.Stdin)
	for {
		// Print prompt
		fmt.Print(opts.Prompt)

		// Check for cancellation, timeout, or signals
		select {
		case <-ctx.Done():
			fmt.Println("\nExiting Gibson console...")
			return cv.shutdown(opts)
		case <-sigChan:
			fmt.Println("\nReceived interrupt signal, exiting Gibson console...")
			return cv.shutdown(opts)
		case <-timeoutChan:
			fmt.Println("\nSession timeout, exiting Gibson console...")
			return cv.shutdown(opts)
		default:
			// Continue with reading input
		}

		// Read user input
		input, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				fmt.Println("\nExiting Gibson console...")
				return cv.shutdown(opts)
			}
			return fmt.Errorf("error reading input: %w", err)
		}

		// Process the command
		if err := cv.processCommand(ctx, input, opts); err != nil {
			if err == io.EOF {
				// User requested exit
				return cv.shutdown(opts)
			}
			fmt.Printf("Error: %v\n", err)
		}
	}
}

// processCommand processes a single command input
func (cv *consoleView) processCommand(ctx context.Context, input string, opts ConsoleOptions) error {
	// Clean up the input
	command := strings.TrimSpace(input)
	if command == "" {
		return nil
	}

	// Add to history
	if opts.History && command != "" {
		cv.addToHistory(command)
	}

	// Handle special console commands
	switch strings.ToLower(command) {
	case "exit", "quit", "q":
		return io.EOF
	case "clear", "cls":
		cv.clearScreen()
		return nil
	case "history":
		cv.showHistory()
		return nil
	case "help":
		cv.showConsoleHelp()
		return nil
	case "commands":
		cv.showAvailableCommands()
		return nil
	}

	// Handle tab completion hints
	if strings.HasPrefix(command, "tab ") {
		return cv.showTabCompletion(command[4:])
	}

	// Simulate command execution (in real implementation, this would delegate to actual command execution)
	return cv.executeGibsonCommand(ctx, command, opts)
}

// executeGibsonCommand simulates executing a Gibson command
func (cv *consoleView) executeGibsonCommand(ctx context.Context, command string, opts ConsoleOptions) error {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return nil
	}

	mainCommand := parts[0]

	// Check if it's a known Gibson command
	if description, exists := cv.commands[mainCommand]; exists {
		if opts.ReadOnly && cv.isWriteCommand(mainCommand) {
			fmt.Printf("Command '%s' is not available in read-only mode\n", mainCommand)
			return nil
		}

		fmt.Printf("Executing: %s\n", command)
		fmt.Printf("Description: %s\n", description)

		// Simulate some processing time
		time.Sleep(100 * time.Millisecond)

		fmt.Println("Command completed successfully.")
		return nil
	}

	return fmt.Errorf("unknown command '%s'. Type 'commands' to see available commands or 'help' for console help", mainCommand)
}

// runBatchCommands executes commands from a batch file
func (cv *consoleView) runBatchCommands(ctx context.Context, opts ConsoleOptions) error {
	file, err := os.Open(opts.BatchFile)
	if err != nil {
		return fmt.Errorf("failed to open batch file '%s': %w", opts.BatchFile, err)
	}
	defer file.Close()

	fmt.Printf("Executing batch commands from: %s\n", opts.BatchFile)
	fmt.Println()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fmt.Printf("[%d] %s%s\n", lineNum, opts.Prompt, line)

		if err := cv.processCommand(ctx, line, opts); err != nil {
			if err == io.EOF {
				break
			}
			fmt.Printf("Error at line %d: %v\n", lineNum, err)
			// Continue with next command in batch mode
		}

		fmt.Println()
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading batch file: %w", err)
	}

	fmt.Println("Batch execution completed.")
	return nil
}

// printWelcome prints the console welcome message
func (cv *consoleView) printWelcome(opts ConsoleOptions) {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   Gibson Interactive Console                 ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Welcome to the Gibson AI/ML Security Testing Interactive Console!")
	fmt.Println()
	fmt.Println("Features:")
	fmt.Printf("  • Command history: %v\n", opts.History)
	fmt.Printf("  • Read-only mode: %v\n", opts.ReadOnly)
	if opts.Timeout > 0 {
		fmt.Printf("  • Session timeout: %d seconds\n", opts.Timeout)
	}
	fmt.Println()
	fmt.Println("Available console commands:")
	fmt.Println("  help      - Show console help")
	fmt.Println("  commands  - List all Gibson commands")
	fmt.Println("  history   - Show command history")
	fmt.Println("  clear     - Clear screen")
	fmt.Println("  exit/quit - Exit console")
	fmt.Println()
	fmt.Println("Type any Gibson command or use tab completion for hints.")
	fmt.Printf("Example: status, target list, scan --help\n")
	fmt.Println()
}

// showConsoleHelp shows help for console-specific features
func (cv *consoleView) showConsoleHelp() {
	fmt.Println("Gibson Interactive Console Help")
	fmt.Println("==============================")
	fmt.Println()
	fmt.Println("Console Commands:")
	fmt.Println("  help                    Show this help message")
	fmt.Println("  commands               List all available Gibson commands")
	fmt.Println("  history                Show command history")
	fmt.Println("  clear, cls             Clear the screen")
	fmt.Println("  exit, quit, q          Exit the console")
	fmt.Println("  tab <partial-command>  Show tab completion suggestions")
	fmt.Println()
	fmt.Println("Gibson Commands:")
	fmt.Println("  All standard Gibson commands are available in the console.")
	fmt.Println("  Examples:")
	fmt.Println("    status                 Show system status")
	fmt.Println("    target list           List targets")
	fmt.Println("    scan --help           Show scan command help")
	fmt.Println("    plugin search ai      Search for AI plugins")
	fmt.Println()
	fmt.Println("Tips:")
	fmt.Println("  • Use arrow keys to navigate command history")
	fmt.Println("  • Commands are executed in the same context")
	fmt.Println("  • Use Ctrl+C to exit")
	fmt.Println("  • Command history is saved between sessions")
}

// showAvailableCommands shows all available Gibson commands
func (cv *consoleView) showAvailableCommands() {
	fmt.Println("Available Gibson Commands")
	fmt.Println("========================")
	fmt.Println()

	// Sort commands for consistent display
	var commands []string
	for cmd := range cv.commands {
		commands = append(commands, cmd)
	}
	sort.Strings(commands)

	for _, cmd := range commands {
		fmt.Printf("  %-12s %s\n", cmd, cv.commands[cmd])
	}

	fmt.Println()
	fmt.Println("Use '<command> --help' for detailed help on any command.")
}

// showTabCompletion shows tab completion suggestions
func (cv *consoleView) showTabCompletion(partial string) error {
	if partial == "" {
		fmt.Println("Tab completion - type 'tab <partial-command>' to see suggestions")
		return nil
	}

	var matches []string
	for cmd := range cv.commands {
		if strings.HasPrefix(cmd, partial) {
			matches = append(matches, cmd)
		}
	}

	if len(matches) == 0 {
		fmt.Printf("No commands found starting with '%s'\n", partial)
		return nil
	}

	fmt.Printf("Tab completion suggestions for '%s':\n", partial)
	sort.Strings(matches)
	for _, match := range matches {
		fmt.Printf("  %s - %s\n", match, cv.commands[match])
	}

	return nil
}

// showHistory displays the command history
func (cv *consoleView) showHistory() {
	if len(cv.history) == 0 {
		fmt.Println("No command history available.")
		return
	}

	fmt.Println("Command History")
	fmt.Println("===============")

	for i, cmd := range cv.history {
		fmt.Printf("%3d  %s\n", i+1, cmd)
	}
}

// addToHistory adds a command to the history
func (cv *consoleView) addToHistory(command string) {
	// Avoid duplicate consecutive commands
	if len(cv.history) > 0 && cv.history[len(cv.history)-1] == command {
		return
	}

	cv.history = append(cv.history, command)

	// Keep history size reasonable
	const maxHistory = 1000
	if len(cv.history) > maxHistory {
		cv.history = cv.history[len(cv.history)-maxHistory:]
	}
}

// loadHistory loads command history from file
func (cv *consoleView) loadHistory() error {
	file, err := os.Open(cv.historyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No history file yet, that's OK
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			cv.history = append(cv.history, line)
		}
	}

	return scanner.Err()
}

// saveHistory saves command history to file
func (cv *consoleView) saveHistory() error {
	if len(cv.history) == 0 {
		return nil
	}

	file, err := os.Create(cv.historyFile)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, cmd := range cv.history {
		if _, err := fmt.Fprintln(file, cmd); err != nil {
			return err
		}
	}

	return nil
}

// clearScreen clears the terminal screen
func (cv *consoleView) clearScreen() {
	fmt.Print("\033[2J\033[H")
}

// shutdown performs cleanup when exiting the console
func (cv *consoleView) shutdown(opts ConsoleOptions) error {
	fmt.Println("Shutting down Gibson console...")

	if opts.History {
		if err := cv.saveHistory(); err != nil {
			slog.Warn("Failed to save command history", "error", err)
		}
	}

	fmt.Println("Goodbye!")
	return nil
}

// isWriteCommand checks if a command is a write operation
func (cv *consoleView) isWriteCommand(command string) bool {
	writeCommands := map[string]bool{
		"scan":       true,
		"target":     true, // Some target operations are write
		"credential": true,
		"plugin":     false, // Plugin operations are mostly read
		"report":     false, // Report operations are mostly read
		"payload":    false, // Payload operations are mostly read
		"status":     false,
		"version":    false,
	}

	return writeCommands[command]
}

// getAvailableCommands returns a map of available Gibson commands
func getAvailableCommands() map[string]string {
	return map[string]string{
		"status":     "Show Gibson system status",
		"scan":       "Manage and execute security scans",
		"target":     "Manage scan targets and endpoints",
		"plugin":     "Manage Gibson security plugins",
		"credential": "Manage authentication credentials",
		"report":     "View and manage scan reports",
		"payload":    "Manage test payloads and datasets",
		"version":    "Show Gibson version information",
		"help":       "Show command help and documentation",
		"console":    "Start interactive console (current mode)",
	}
}