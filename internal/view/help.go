// Package view provides help view implementation for enhanced help system
package view

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// helpView implements an enhanced help system following k9s patterns
type helpView struct {
	topics    map[string]*HelpTopic
	searchIdx map[string][]string // Search index: word -> topic names
}

// HelpOptions defines options for the help system
type HelpOptions struct {
	Topic       string
	Interactive bool
	Format      string
	Search      string
	Verbose     bool
}

// HelpTopic represents a help topic with content and metadata
type HelpTopic struct {
	Name        string            `json:"name" yaml:"name"`
	Title       string            `json:"title" yaml:"title"`
	Description string            `json:"description" yaml:"description"`
	Content     string            `json:"content" yaml:"content"`
	Examples    []HelpExample     `json:"examples,omitempty" yaml:"examples,omitempty"`
	SeeAlso     []string          `json:"see_also,omitempty" yaml:"see_also,omitempty"`
	Tags        []string          `json:"tags,omitempty" yaml:"tags,omitempty"`
	LastUpdated time.Time         `json:"last_updated" yaml:"last_updated"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// HelpExample represents a usage example
type HelpExample struct {
	Title       string `json:"title" yaml:"title"`
	Description string `json:"description" yaml:"description"`
	Command     string `json:"command" yaml:"command"`
	Output      string `json:"output,omitempty" yaml:"output,omitempty"`
}

// NewHelpView creates a new help view instance
func NewHelpView() *helpView {
	hv := &helpView{
		topics:    make(map[string]*HelpTopic),
		searchIdx: make(map[string][]string),
	}

	// Initialize help topics
	hv.initializeTopics()
	hv.buildSearchIndex()

	return hv
}

// ShowHelp displays help based on the provided options
func (hv *helpView) ShowHelp(ctx context.Context, opts HelpOptions) error {
	// Operation completed - silent logging

	// Handle search
	if opts.Search != "" {
		return hv.searchHelp(opts)
	}

	// Handle interactive mode
	if opts.Interactive {
		return hv.startInteractiveHelp(ctx, opts)
	}

	// Handle specific topic
	if opts.Topic != "" {
		return hv.showTopic(opts.Topic, opts)
	}

	// Show general help overview
	return hv.showOverview(opts)
}

// startInteractiveHelp starts the interactive help browser
func (hv *helpView) startInteractiveHelp(ctx context.Context, opts HelpOptions) error {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                Gibson Interactive Help Browser               ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("Navigation:")
	fmt.Println("  • Type topic name or number to view")
	fmt.Println("  • Type 'search <term>' to search help content")
	fmt.Println("  • Type 'list' to show all topics")
	fmt.Println("  • Type 'back' to return to topic list")
	fmt.Println("  • Type 'quit' or 'exit' to exit")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)
	currentTopic := ""

	for {
		// Show current context
		if currentTopic == "" {
			hv.showTopicList()
		}

		// Show prompt
		if currentTopic != "" {
			fmt.Printf("help[%s]> ", currentTopic)
		} else {
			fmt.Print("help> ")
		}

		// Read input
		input, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("error reading input: %w", err)
		}

		command := strings.TrimSpace(input)
		if command == "" {
			continue
		}

		// Handle commands
		switch {
		case command == "quit" || command == "exit" || command == "q":
			fmt.Println("Exiting help browser...")
			return nil

		case command == "list" || command == "ls":
			currentTopic = ""
			hv.showTopicList()

		case command == "back" || command == "..":
			currentTopic = ""

		case strings.HasPrefix(command, "search "):
			searchTerm := strings.TrimPrefix(command, "search ")
			searchOpts := opts
			searchOpts.Search = searchTerm
			hv.searchHelp(searchOpts)

		case command == "help":
			hv.showInteractiveHelp()

		default:
			// Try to find and display a topic
			if topic := hv.findTopic(command); topic != nil {
				currentTopic = topic.Name
				hv.displayTopic(topic, opts)
			} else {
				fmt.Printf("Unknown topic '%s'. Type 'list' to see available topics.\n", command)
			}
		}

		fmt.Println()
	}
}

// showOverview displays the general help overview
func (hv *helpView) showOverview(opts HelpOptions) error {
	overview := &HelpTopic{
		Name:  "overview",
		Title: "Gibson AI/ML Security Testing Framework",
		Content: `Gibson is a comprehensive CLI framework for AI/ML security testing and assessment.
It provides tools for scanning, analyzing, and testing the security of AI/ML systems
across multiple domains including models, data, interfaces, infrastructure, output, and processes.

Key Features:
  • Multi-domain security testing (Model, Data, Interface, Infrastructure, Output, Process)
  • Plugin-based architecture for extensible testing capabilities
  • Interactive console with command history and tab completion
  • Comprehensive reporting and audit trails
  • Support for multiple AI/ML platforms and providers
  • Batch processing and automation support`,
		Examples: []HelpExample{
			{
				Title:       "Getting Started",
				Description: "Basic commands to get started with Gibson",
				Command:     "gibson status",
			},
			{
				Title:       "Quick Scan",
				Description: "Run a quick security scan on a target",
				Command:     "gibson scan --target my-model --quick",
			},
		},
		SeeAlso: []string{"quickstart", "commands", "scanning", "targets"},
	}

	return hv.displayTopic(overview, opts)
}

// showTopic displays a specific help topic
func (hv *helpView) showTopic(topicName string, opts HelpOptions) error {
	topic := hv.topics[topicName]
	if topic == nil {
		return fmt.Errorf("help topic '%s' not found. Use 'gibson help list' to see available topics", topicName)
	}

	return hv.displayTopic(topic, opts)
}

// displayTopic displays a help topic in the specified format
func (hv *helpView) displayTopic(topic *HelpTopic, opts HelpOptions) error {
	switch opts.Format {
	case "json":
		return hv.displayTopicJSON(topic)
	case "yaml":
		return hv.displayTopicYAML(topic)
	default:
		return hv.displayTopicText(topic, opts.Verbose)
	}
}

// displayTopicText displays a topic in text format
func (hv *helpView) displayTopicText(topic *HelpTopic, verbose bool) error {
	fmt.Printf("╔═══ %s ═══╗\n", strings.ToUpper(topic.Title))
	fmt.Printf("║ %s ║\n", topic.Name)
	fmt.Println("╚" + strings.Repeat("═", len(topic.Title)+8) + "╝")
	fmt.Println()

	if topic.Description != "" {
		fmt.Println("Description:")
		fmt.Printf("  %s\n", topic.Description)
		fmt.Println()
	}

	if topic.Content != "" {
		fmt.Println("Content:")
		// Format content with proper indentation
		lines := strings.Split(topic.Content, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				fmt.Println()
			} else {
				fmt.Printf("  %s\n", line)
			}
		}
		fmt.Println()
	}

	// Show examples
	if len(topic.Examples) > 0 {
		fmt.Println("Examples:")
		for i, example := range topic.Examples {
			fmt.Printf("  %d. %s\n", i+1, example.Title)
			if example.Description != "" {
				fmt.Printf("     %s\n", example.Description)
			}
			fmt.Printf("     $ %s\n", example.Command)
			if verbose && example.Output != "" {
				fmt.Println("     Output:")
				outputLines := strings.Split(example.Output, "\n")
				for _, line := range outputLines {
					fmt.Printf("     > %s\n", line)
				}
			}
			fmt.Println()
		}
	}

	// Show tags if verbose
	if verbose && len(topic.Tags) > 0 {
		fmt.Printf("Tags: %s\n", strings.Join(topic.Tags, ", "))
		fmt.Println()
	}

	// Show see also
	if len(topic.SeeAlso) > 0 {
		fmt.Printf("See also: %s\n", strings.Join(topic.SeeAlso, ", "))
		fmt.Println()
	}

	// Show metadata if verbose
	if verbose && len(topic.Metadata) > 0 {
		fmt.Println("Metadata:")
		for key, value := range topic.Metadata {
			fmt.Printf("  %s: %s\n", key, value)
		}
		fmt.Println()
	}

	return nil
}

// displayTopicJSON displays a topic in JSON format
func (hv *helpView) displayTopicJSON(topic *HelpTopic) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(topic)
}

// displayTopicYAML displays a topic in YAML format
func (hv *helpView) displayTopicYAML(topic *HelpTopic) error {
	encoder := yaml.NewEncoder(os.Stdout)
	defer encoder.Close()
	return encoder.Encode(topic)
}

// searchHelp searches help content for the specified term
func (hv *helpView) searchHelp(opts HelpOptions) error {
	searchTerm := strings.ToLower(opts.Search)
	var matches []*HelpTopic

	// Search in search index first
	if topicNames, exists := hv.searchIdx[searchTerm]; exists {
		for _, name := range topicNames {
			if topic := hv.topics[name]; topic != nil {
				matches = append(matches, topic)
			}
		}
	}

	// Also search in content for partial matches
	for _, topic := range hv.topics {
		// Skip if already found in index
		found := false
		for _, match := range matches {
			if match.Name == topic.Name {
				found = true
				break
			}
		}
		if found {
			continue
		}

		// Search in various fields
		if strings.Contains(strings.ToLower(topic.Title), searchTerm) ||
			strings.Contains(strings.ToLower(topic.Description), searchTerm) ||
			strings.Contains(strings.ToLower(topic.Content), searchTerm) {
			matches = append(matches, topic)
		}
	}

	if len(matches) == 0 {
		fmt.Printf("No help topics found matching '%s'\n", opts.Search)
		return nil
	}

	fmt.Printf("Search Results for '%s' (%d found):\n", opts.Search, len(matches))
	fmt.Println(strings.Repeat("=", 50))

	for i, topic := range matches {
		fmt.Printf("%d. %s - %s\n", i+1, topic.Title, topic.Name)
		if topic.Description != "" {
			fmt.Printf("   %s\n", topic.Description)
		}
		fmt.Println()
	}

	return nil
}

// showTopicList displays all available topics
func (hv *helpView) showTopicList() {
	fmt.Println("Available Help Topics:")
	fmt.Println("=====================")

	// Group topics by category
	categories := map[string][]*HelpTopic{
		"Getting Started": {},
		"Commands":        {},
		"Concepts":        {},
		"Advanced":        {},
		"Reference":       {},
	}

	for _, topic := range hv.topics {
		category := "Commands" // default
		if cat, exists := topic.Metadata["category"]; exists {
			category = cat
		}
		categories[category] = append(categories[category], topic)
	}

	// Display by category
	for category, topics := range categories {
		if len(topics) == 0 {
			continue
		}

		fmt.Printf("\n%s:\n", category)
		sort.Slice(topics, func(i, j int) bool {
			return topics[i].Name < topics[j].Name
		})

		for _, topic := range topics {
			fmt.Printf("  %-15s %s\n", topic.Name, topic.Description)
		}
	}

	fmt.Println()
}

// showInteractiveHelp shows help for the interactive browser
func (hv *helpView) showInteractiveHelp() {
	fmt.Println("Interactive Help Browser Commands:")
	fmt.Println("=================================")
	fmt.Println("  <topic>         View specific help topic")
	fmt.Println("  <number>        View topic by number from list")
	fmt.Println("  search <term>   Search help content")
	fmt.Println("  list, ls        Show all available topics")
	fmt.Println("  back, ..        Return to topic list")
	fmt.Println("  help            Show this help")
	fmt.Println("  quit, exit, q   Exit help browser")
}

// findTopic finds a topic by name or number
func (hv *helpView) findTopic(input string) *HelpTopic {
	// Try direct name lookup first
	if topic := hv.topics[input]; topic != nil {
		return topic
	}

	// Try number lookup
	if num, err := strconv.Atoi(input); err == nil {
		var topics []*HelpTopic
		for _, topic := range hv.topics {
			topics = append(topics, topic)
		}
		sort.Slice(topics, func(i, j int) bool {
			return topics[i].Name < topics[j].Name
		})

		if num > 0 && num <= len(topics) {
			return topics[num-1]
		}
	}

	// Try partial name match
	for name, topic := range hv.topics {
		if strings.HasPrefix(name, input) {
			return topic
		}
	}

	return nil
}

// buildSearchIndex builds a search index for quick lookups
func (hv *helpView) buildSearchIndex() {
	for name, topic := range hv.topics {
		// Index all words from title, description, and tags
		words := []string{}
		words = append(words, strings.Fields(strings.ToLower(topic.Title))...)
		words = append(words, strings.Fields(strings.ToLower(topic.Description))...)
		for _, tag := range topic.Tags {
			words = append(words, strings.ToLower(tag))
		}

		// Add to search index
		for _, word := range words {
			word = strings.TrimSpace(word)
			if word != "" {
				hv.searchIdx[word] = append(hv.searchIdx[word], name)
			}
		}
	}
}

// initializeTopics initializes all help topics
func (hv *helpView) initializeTopics() {
	now := time.Now()

	// Getting Started topics
	hv.topics["quickstart"] = &HelpTopic{
		Name:        "quickstart",
		Title:       "Quick Start Guide",
		Description: "Get started with Gibson in 5 minutes",
		Content: `Welcome to Gibson! This guide will help you get started with AI/ML security testing.

Step 1: Check System Status
First, verify Gibson is working correctly:
  $ gibson status

Step 2: List Available Commands
See all available commands:
  $ gibson help commands

Step 3: Set Up a Target
Add your first AI/ML target:
  $ gibson target add my-model --endpoint https://api.example.com/predict

Step 4: Run Your First Scan
Execute a basic security scan:
  $ gibson scan --target my-model --type quick

Step 5: View Results
Check the scan results:
  $ gibson report list
  $ gibson report show <scan-id>`,
		Examples: []HelpExample{
			{
				Title:       "Basic Setup",
				Description: "Complete basic setup and first scan",
				Command:     "gibson status && gibson target add demo --endpoint http://localhost:8080",
			},
		},
		Tags:        []string{"beginner", "setup", "tutorial"},
		LastUpdated: now,
		Metadata:    map[string]string{"category": "Getting Started", "difficulty": "beginner"},
	}

	hv.topics["commands"] = &HelpTopic{
		Name:        "commands",
		Title:       "Command Reference",
		Description: "Complete reference of all Gibson commands",
		Content: `Gibson provides the following main commands:

scan        - Execute security scans on AI/ML targets
target      - Manage scan targets and endpoints
plugin      - Manage security testing plugins
credential  - Manage authentication credentials
report      - View and manage scan reports
payload     - Manage test payloads and datasets
status      - Show system status and health
console     - Start interactive console
help        - Show help and documentation
version     - Show version information

Each command has subcommands and options. Use --help with any command for details.`,
		Examples: []HelpExample{
			{
				Title:       "Get Command Help",
				Description: "Show detailed help for any command",
				Command:     "gibson scan --help",
			},
			{
				Title:       "List Subcommands",
				Description: "See all subcommands for a command",
				Command:     "gibson target --help",
			},
		},
		Tags:        []string{"reference", "commands"},
		LastUpdated: now,
		Metadata:    map[string]string{"category": "Reference"},
	}

	hv.topics["scanning"] = &HelpTopic{
		Name:        "scanning",
		Title:       "Security Scanning",
		Description: "How to perform AI/ML security scans",
		Content: `Gibson supports comprehensive security scanning across six domains:

1. Model Domain: Test AI models for extraction, inversion, backdoor, and adversarial attacks
2. Data Domain: Test training and inference data for poisoning and quality issues
3. Interface Domain: Test prompts and interfaces for injection and jailbreak attacks
4. Infrastructure Domain: Test deployment infrastructure for DoS and auth bypass
5. Output Domain: Test model outputs for data leakage and harmful content
6. Process Domain: Test development processes for supply chain vulnerabilities

Scan Types:
  • Quick scan: Fast basic security checks
  • Full scan: Comprehensive security assessment
  • Custom scan: User-defined test combinations
  • Continuous scan: Automated recurring scans`,
		Examples: []HelpExample{
			{
				Title:       "Quick Security Scan",
				Description: "Run a fast basic security check",
				Command:     "gibson scan --target my-model --type quick",
			},
			{
				Title:       "Full Security Assessment",
				Description: "Comprehensive security scan across all domains",
				Command:     "gibson scan --target my-model --type full --domains all",
			},
			{
				Title:       "Domain-Specific Scan",
				Description: "Scan specific security domains",
				Command:     "gibson scan --target my-model --domains model,data,interface",
			},
		},
		SeeAlso:     []string{"targets", "plugins", "reports"},
		Tags:        []string{"scanning", "security", "testing"},
		LastUpdated: now,
		Metadata:    map[string]string{"category": "Concepts"},
	}

	hv.topics["targets"] = &HelpTopic{
		Name:        "targets",
		Title:       "Managing Targets",
		Description: "How to configure and manage scan targets",
		Content: `Targets represent the AI/ML systems you want to test. Gibson supports various target types:

Target Types:
  • REST API endpoints
  • GraphQL endpoints
  • gRPC services
  • WebSocket connections
  • Local model files
  • Model registry endpoints

Target Configuration:
  • Authentication credentials
  • Request/response formats
  • Rate limiting settings
  • Custom headers and parameters`,
		Examples: []HelpExample{
			{
				Title:       "Add REST API Target",
				Description: "Add a REST API endpoint as a target",
				Command:     "gibson target add api-model --endpoint https://api.example.com/predict --type rest",
			},
			{
				Title:       "Add Authenticated Target",
				Description: "Add target with authentication",
				Command:     "gibson target add secure-model --endpoint https://api.example.com --credential my-token",
			},
		},
		SeeAlso:     []string{"credentials", "scanning"},
		Tags:        []string{"targets", "configuration"},
		LastUpdated: now,
		Metadata:    map[string]string{"category": "Concepts"},
	}

	hv.topics["plugins"] = &HelpTopic{
		Name:        "plugins",
		Title:       "Plugin System",
		Description: "Understanding and managing Gibson plugins",
		Content: `Gibson uses a plugin-based architecture for extensible security testing.

Plugin Domains:
  • Model: AI model-specific attacks and tests
  • Data: Data quality and poisoning tests
  • Interface: Prompt injection and interface tests
  • Infrastructure: Infrastructure and deployment tests
  • Output: Output analysis and content filtering
  • Process: Development process and supply chain tests

Plugin Management:
  • Install new plugins from repositories
  • Enable/disable plugins for scans
  • Configure plugin-specific settings
  • Develop custom plugins`,
		Examples: []HelpExample{
			{
				Title:       "List Available Plugins",
				Description: "Show all available security plugins",
				Command:     "gibson plugin list",
			},
			{
				Title:       "Search for Plugins",
				Description: "Find plugins for specific purposes",
				Command:     "gibson plugin search adversarial",
			},
		},
		SeeAlso:     []string{"scanning", "domains"},
		Tags:        []string{"plugins", "extensibility"},
		LastUpdated: now,
		Metadata:    map[string]string{"category": "Advanced"},
	}

	hv.topics["console"] = &HelpTopic{
		Name:        "console",
		Title:       "Interactive Console",
		Description: "Using Gibson's interactive console mode",
		Content: `The Gibson console provides an interactive REPL environment for security testing.

Console Features:
  • Command history with arrow key navigation
  • Tab completion for commands and arguments
  • Persistent session context
  • Batch command execution
  • Read-only mode for safe exploration

Console Commands:
  • All Gibson commands work in console mode
  • Special console commands: history, clear, exit
  • Tab completion shows available options`,
		Examples: []HelpExample{
			{
				Title:       "Start Interactive Console",
				Description: "Launch the Gibson console",
				Command:     "gibson console",
			},
			{
				Title:       "Console with Custom Prompt",
				Description: "Start console with custom prompt",
				Command:     "gibson console --prompt 'gibson-test> '",
			},
		},
		SeeAlso:     []string{"commands", "quickstart"},
		Tags:        []string{"console", "interactive", "repl"},
		LastUpdated: now,
		Metadata:    map[string]string{"category": "Advanced"},
	}

	// Add more topics as needed...
}