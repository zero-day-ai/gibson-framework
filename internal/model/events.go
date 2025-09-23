// Package model provides event system interfaces following k9s patterns
package model

import (
	"time"
)

// ScanEvent represents different types of scan events
type ScanEvent struct {
	ID        string                 `json:"id"`
	Type      ScanEventType         `json:"type"`
	Timestamp time.Time             `json:"timestamp"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Error     error                 `json:"error,omitempty"`
}

// ScanEventType defines the type of scan event
type ScanEventType string

const (
	ScanEventStarted   ScanEventType = "started"
	ScanEventUpdated   ScanEventType = "updated"
	ScanEventCompleted ScanEventType = "completed"
	ScanEventFailed    ScanEventType = "failed"
)

// ScanEventListener represents a scan event listener following k9s pattern
type ScanEventListener interface {
	// ScanStarted notifies listener that a scan has started
	ScanStarted(event *ScanEvent)

	// ScanUpdated notifies listener that scan progress has updated
	ScanUpdated(event *ScanEvent)

	// ScanCompleted notifies listener that a scan has completed successfully
	ScanCompleted(event *ScanEvent)

	// ScanFailed notifies listener that a scan has failed
	ScanFailed(event *ScanEvent)
}

// TargetEvent represents different types of target events
type TargetEvent struct {
	ID        string                 `json:"id"`
	Type      TargetEventType       `json:"type"`
	Timestamp time.Time             `json:"timestamp"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Error     error                 `json:"error,omitempty"`
}

// TargetEventType defines the type of target event
type TargetEventType string

const (
	TargetEventStarted   TargetEventType = "started"
	TargetEventUpdated   TargetEventType = "updated"
	TargetEventCompleted TargetEventType = "completed"
	TargetEventFailed    TargetEventType = "failed"
)

// TargetEventListener represents a target event listener following k9s pattern
type TargetEventListener interface {
	// TargetStarted notifies listener that target processing has started
	TargetStarted(event *TargetEvent)

	// TargetUpdated notifies listener that target data has updated
	TargetUpdated(event *TargetEvent)

	// TargetCompleted notifies listener that target processing has completed
	TargetCompleted(event *TargetEvent)

	// TargetFailed notifies listener that target processing has failed
	TargetFailed(event *TargetEvent)
}

// FindingEvent represents different types of finding events
type FindingEvent struct {
	ID        string                 `json:"id"`
	Type      FindingEventType      `json:"type"`
	Timestamp time.Time             `json:"timestamp"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Error     error                 `json:"error,omitempty"`
}

// FindingEventType defines the type of finding event
type FindingEventType string

const (
	FindingEventStarted   FindingEventType = "started"
	FindingEventUpdated   FindingEventType = "updated"
	FindingEventCompleted FindingEventType = "completed"
	FindingEventFailed    FindingEventType = "failed"
)

// FindingEventListener represents a finding event listener following k9s pattern
type FindingEventListener interface {
	// FindingStarted notifies listener that finding processing has started
	FindingStarted(event *FindingEvent)

	// FindingUpdated notifies listener that finding data has updated
	FindingUpdated(event *FindingEvent)

	// FindingCompleted notifies listener that finding processing has completed
	FindingCompleted(event *FindingEvent)

	// FindingFailed notifies listener that finding processing has failed
	FindingFailed(event *FindingEvent)
}