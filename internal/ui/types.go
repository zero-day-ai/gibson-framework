// Package ui provides UI types for Gibson
package ui

// KeyActions manages keyboard action bindings
type KeyActions struct {
	actions map[Key]KeyAction
}

// KeyAction represents a keyboard action
type KeyAction struct {
	Key         Key
	Description string
	Action      func()
}

// Key represents keyboard keys
type Key int

const (
	KeyQ Key = iota
	KeyR
	KeyEscape
	KeyEnter
	KeyS
	KeyX
	KeyD
	KeyA
	KeyE
	KeyT
	KeyU
	KeyI
	KeyF
	KeyC
	Key1
	Key2
	Key3
	Key4
)

// NewKeyActions creates new key actions manager
func NewKeyActions() *KeyActions {
	return &KeyActions{
		actions: make(map[Key]KeyAction),
	}
}

// Add adds a key action
func (ka *KeyActions) Add(action KeyAction) {
	ka.actions[action.Key] = action
}

// Get gets a key action
func (ka *KeyActions) Get(key Key) (KeyAction, bool) {
	action, exists := ka.actions[key]
	return action, exists
}

// Styles represents UI styling
type Styles struct {
	// Styling implementation would go here
}

// NewStyles creates new styles
func NewStyles() *Styles {
	return &Styles{}
}

// Tabular represents tabular UI component
type Tabular interface {
	// GetData returns tabular data
	GetData() [][]string

	// GetHeaders returns column headers
	GetHeaders() []string

	// GetRowCount returns number of rows
	GetRowCount() int
}