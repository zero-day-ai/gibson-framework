// Package config provides configuration management for Gibson
package config

const (
	AppName             = "gibson"
	DefaultRefreshRate  = 2.0
	DefaultLogLevel     = "info"
	AppLogFile          = "/tmp/gibson.log"
	DefaultCommand      = "scan"
)

// Flags represents CLI flags
type Flags struct {
	RefreshRate    *float32
	LogLevel       *string
	LogFile        *string
	Headless       *bool
	Logoless       *bool
	Crumbsless     *bool
	Splashless     *bool
	AllTargets     *bool
	Command        *string
	ReadOnly       *bool
	Write          *bool
	ScreenDumpDir  *string
	ConfigFile     *string
}

// NewFlags creates a new Flags instance
func NewFlags() *Flags {
	refreshRate := float32(DefaultRefreshRate)
	logLevel := DefaultLogLevel
	logFile := AppLogFile
	command := DefaultCommand

	return &Flags{
		RefreshRate:    &refreshRate,
		LogLevel:       &logLevel,
		LogFile:        &logFile,
		Headless:       new(bool),
		Logoless:       new(bool),
		Crumbsless:     new(bool),
		Splashless:     new(bool),
		AllTargets:     new(bool),
		Command:        &command,
		ReadOnly:       new(bool),
		Write:          new(bool),
		ScreenDumpDir:  new(string),
		ConfigFile:     new(string),
	}
}