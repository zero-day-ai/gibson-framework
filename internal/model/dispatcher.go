// Package model provides event dispatcher following k9s patterns
package model

import (
	"sync"
	"time"
)

// EventDispatcher manages event listeners and dispatches events (following k9s pattern)
type EventDispatcher struct {
	scanListeners    []ScanEventListener
	targetListeners  []TargetEventListener
	findingListeners []FindingEventListener
	mx               sync.RWMutex
}

// NewEventDispatcher creates a new event dispatcher
func NewEventDispatcher() *EventDispatcher {
	return &EventDispatcher{}
}

// AddScanListener adds a new scan event listener (following k9s AddListener pattern)
func (d *EventDispatcher) AddScanListener(l ScanEventListener) {
	d.mx.Lock()
	defer d.mx.Unlock()
	d.scanListeners = append(d.scanListeners, l)
}

// RemoveScanListener removes a scan event listener (following k9s RemoveListener pattern)
func (d *EventDispatcher) RemoveScanListener(l ScanEventListener) {
	d.mx.Lock()
	defer d.mx.Unlock()

	victim := -1
	for i, lis := range d.scanListeners {
		if lis == l {
			victim = i
			break
		}
	}

	if victim >= 0 {
		d.scanListeners = append(d.scanListeners[:victim], d.scanListeners[victim+1:]...)
	}
}

// AddTargetListener adds a new target event listener (following k9s AddListener pattern)
func (d *EventDispatcher) AddTargetListener(l TargetEventListener) {
	d.mx.Lock()
	defer d.mx.Unlock()
	d.targetListeners = append(d.targetListeners, l)
}

// RemoveTargetListener removes a target event listener (following k9s RemoveListener pattern)
func (d *EventDispatcher) RemoveTargetListener(l TargetEventListener) {
	d.mx.Lock()
	defer d.mx.Unlock()

	victim := -1
	for i, lis := range d.targetListeners {
		if lis == l {
			victim = i
			break
		}
	}

	if victim >= 0 {
		d.targetListeners = append(d.targetListeners[:victim], d.targetListeners[victim+1:]...)
	}
}

// AddFindingListener adds a new finding event listener (following k9s AddListener pattern)
func (d *EventDispatcher) AddFindingListener(l FindingEventListener) {
	d.mx.Lock()
	defer d.mx.Unlock()
	d.findingListeners = append(d.findingListeners, l)
}

// RemoveFindingListener removes a finding event listener (following k9s RemoveListener pattern)
func (d *EventDispatcher) RemoveFindingListener(l FindingEventListener) {
	d.mx.Lock()
	defer d.mx.Unlock()

	victim := -1
	for i, lis := range d.findingListeners {
		if lis == l {
			victim = i
			break
		}
	}

	if victim >= 0 {
		d.findingListeners = append(d.findingListeners[:victim], d.findingListeners[victim+1:]...)
	}
}

// FireScanStarted notifies all scan listeners that a scan has started (following k9s fire* pattern)
func (d *EventDispatcher) FireScanStarted(id string, data map[string]interface{}) {
	event := &ScanEvent{
		ID:        id,
		Type:      ScanEventStarted,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Non-blocking dispatch using goroutine (following k9s pattern)
	go func() {
		d.mx.RLock()
		listeners := make([]ScanEventListener, len(d.scanListeners))
		copy(listeners, d.scanListeners)
		d.mx.RUnlock()

		for _, l := range listeners {
			l.ScanStarted(event)
		}
	}()
}

// FireScanUpdated notifies all scan listeners that a scan has updated (following k9s fire* pattern)
func (d *EventDispatcher) FireScanUpdated(id string, data map[string]interface{}) {
	event := &ScanEvent{
		ID:        id,
		Type:      ScanEventUpdated,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Non-blocking dispatch using goroutine (following k9s pattern)
	go func() {
		d.mx.RLock()
		listeners := make([]ScanEventListener, len(d.scanListeners))
		copy(listeners, d.scanListeners)
		d.mx.RUnlock()

		for _, l := range listeners {
			l.ScanUpdated(event)
		}
	}()
}

// FireScanCompleted notifies all scan listeners that a scan has completed (following k9s fire* pattern)
func (d *EventDispatcher) FireScanCompleted(id string, data map[string]interface{}) {
	event := &ScanEvent{
		ID:        id,
		Type:      ScanEventCompleted,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Non-blocking dispatch using goroutine (following k9s pattern)
	go func() {
		d.mx.RLock()
		listeners := make([]ScanEventListener, len(d.scanListeners))
		copy(listeners, d.scanListeners)
		d.mx.RUnlock()

		for _, l := range listeners {
			l.ScanCompleted(event)
		}
	}()
}

// FireScanFailed notifies all scan listeners that a scan has failed (following k9s fire* pattern)
func (d *EventDispatcher) FireScanFailed(id string, err error, data map[string]interface{}) {
	event := &ScanEvent{
		ID:        id,
		Type:      ScanEventFailed,
		Timestamp: time.Now(),
		Data:      data,
		Error:     err,
	}

	// Non-blocking dispatch using goroutine (following k9s pattern)
	go func() {
		d.mx.RLock()
		listeners := make([]ScanEventListener, len(d.scanListeners))
		copy(listeners, d.scanListeners)
		d.mx.RUnlock()

		for _, l := range listeners {
			l.ScanFailed(event)
		}
	}()
}

// FireTargetStarted notifies all target listeners that target processing has started (following k9s fire* pattern)
func (d *EventDispatcher) FireTargetStarted(id string, data map[string]interface{}) {
	event := &TargetEvent{
		ID:        id,
		Type:      TargetEventStarted,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Non-blocking dispatch using goroutine (following k9s pattern)
	go func() {
		d.mx.RLock()
		listeners := make([]TargetEventListener, len(d.targetListeners))
		copy(listeners, d.targetListeners)
		d.mx.RUnlock()

		for _, l := range listeners {
			l.TargetStarted(event)
		}
	}()
}

// FireTargetUpdated notifies all target listeners that target data has updated (following k9s fire* pattern)
func (d *EventDispatcher) FireTargetUpdated(id string, data map[string]interface{}) {
	event := &TargetEvent{
		ID:        id,
		Type:      TargetEventUpdated,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Non-blocking dispatch using goroutine (following k9s pattern)
	go func() {
		d.mx.RLock()
		listeners := make([]TargetEventListener, len(d.targetListeners))
		copy(listeners, d.targetListeners)
		d.mx.RUnlock()

		for _, l := range listeners {
			l.TargetUpdated(event)
		}
	}()
}

// FireTargetCompleted notifies all target listeners that target processing has completed (following k9s fire* pattern)
func (d *EventDispatcher) FireTargetCompleted(id string, data map[string]interface{}) {
	event := &TargetEvent{
		ID:        id,
		Type:      TargetEventCompleted,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Non-blocking dispatch using goroutine (following k9s pattern)
	go func() {
		d.mx.RLock()
		listeners := make([]TargetEventListener, len(d.targetListeners))
		copy(listeners, d.targetListeners)
		d.mx.RUnlock()

		for _, l := range listeners {
			l.TargetCompleted(event)
		}
	}()
}

// FireTargetFailed notifies all target listeners that target processing has failed (following k9s fire* pattern)
func (d *EventDispatcher) FireTargetFailed(id string, err error, data map[string]interface{}) {
	event := &TargetEvent{
		ID:        id,
		Type:      TargetEventFailed,
		Timestamp: time.Now(),
		Data:      data,
		Error:     err,
	}

	// Non-blocking dispatch using goroutine (following k9s pattern)
	go func() {
		d.mx.RLock()
		listeners := make([]TargetEventListener, len(d.targetListeners))
		copy(listeners, d.targetListeners)
		d.mx.RUnlock()

		for _, l := range listeners {
			l.TargetFailed(event)
		}
	}()
}

// FireFindingStarted notifies all finding listeners that finding processing has started (following k9s fire* pattern)
func (d *EventDispatcher) FireFindingStarted(id string, data map[string]interface{}) {
	event := &FindingEvent{
		ID:        id,
		Type:      FindingEventStarted,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Non-blocking dispatch using goroutine (following k9s pattern)
	go func() {
		d.mx.RLock()
		listeners := make([]FindingEventListener, len(d.findingListeners))
		copy(listeners, d.findingListeners)
		d.mx.RUnlock()

		for _, l := range listeners {
			l.FindingStarted(event)
		}
	}()
}

// FireFindingUpdated notifies all finding listeners that finding data has updated (following k9s fire* pattern)
func (d *EventDispatcher) FireFindingUpdated(id string, data map[string]interface{}) {
	event := &FindingEvent{
		ID:        id,
		Type:      FindingEventUpdated,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Non-blocking dispatch using goroutine (following k9s pattern)
	go func() {
		d.mx.RLock()
		listeners := make([]FindingEventListener, len(d.findingListeners))
		copy(listeners, d.findingListeners)
		d.mx.RUnlock()

		for _, l := range listeners {
			l.FindingUpdated(event)
		}
	}()
}

// FireFindingCompleted notifies all finding listeners that finding processing has completed (following k9s fire* pattern)
func (d *EventDispatcher) FireFindingCompleted(id string, data map[string]interface{}) {
	event := &FindingEvent{
		ID:        id,
		Type:      FindingEventCompleted,
		Timestamp: time.Now(),
		Data:      data,
	}

	// Non-blocking dispatch using goroutine (following k9s pattern)
	go func() {
		d.mx.RLock()
		listeners := make([]FindingEventListener, len(d.findingListeners))
		copy(listeners, d.findingListeners)
		d.mx.RUnlock()

		for _, l := range listeners {
			l.FindingCompleted(event)
		}
	}()
}

// FireFindingFailed notifies all finding listeners that finding processing has failed (following k9s fire* pattern)
func (d *EventDispatcher) FireFindingFailed(id string, err error, data map[string]interface{}) {
	event := &FindingEvent{
		ID:        id,
		Type:      FindingEventFailed,
		Timestamp: time.Now(),
		Data:      data,
		Error:     err,
	}

	// Non-blocking dispatch using goroutine (following k9s pattern)
	go func() {
		d.mx.RLock()
		listeners := make([]FindingEventListener, len(d.findingListeners))
		copy(listeners, d.findingListeners)
		d.mx.RUnlock()

		for _, l := range listeners {
			l.FindingFailed(event)
		}
	}()
}

// GetListenerCounts returns the count of listeners for each event type (for debugging/monitoring)
func (d *EventDispatcher) GetListenerCounts() map[string]int {
	d.mx.RLock()
	defer d.mx.RUnlock()

	return map[string]int{
		"scan":    len(d.scanListeners),
		"target":  len(d.targetListeners),
		"finding": len(d.findingListeners),
	}
}