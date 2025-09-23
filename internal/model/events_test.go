package model

import (
	"sync"
	"testing"
	"time"
)

// TestListener implements all three listener interfaces for testing
type TestListener struct {
	scanEvents    []*ScanEvent
	targetEvents  []*TargetEvent
	findingEvents []*FindingEvent
	mu            sync.Mutex
}

func (t *TestListener) ScanStarted(event *ScanEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.scanEvents = append(t.scanEvents, event)
}

func (t *TestListener) ScanUpdated(event *ScanEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.scanEvents = append(t.scanEvents, event)
}

func (t *TestListener) ScanCompleted(event *ScanEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.scanEvents = append(t.scanEvents, event)
}

func (t *TestListener) ScanFailed(event *ScanEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.scanEvents = append(t.scanEvents, event)
}

func (t *TestListener) TargetStarted(event *TargetEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.targetEvents = append(t.targetEvents, event)
}

func (t *TestListener) TargetUpdated(event *TargetEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.targetEvents = append(t.targetEvents, event)
}

func (t *TestListener) TargetCompleted(event *TargetEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.targetEvents = append(t.targetEvents, event)
}

func (t *TestListener) TargetFailed(event *TargetEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.targetEvents = append(t.targetEvents, event)
}

func (t *TestListener) FindingStarted(event *FindingEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.findingEvents = append(t.findingEvents, event)
}

func (t *TestListener) FindingUpdated(event *FindingEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.findingEvents = append(t.findingEvents, event)
}

func (t *TestListener) FindingCompleted(event *FindingEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.findingEvents = append(t.findingEvents, event)
}

func (t *TestListener) FindingFailed(event *FindingEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.findingEvents = append(t.findingEvents, event)
}

func (t *TestListener) GetEventCounts() (int, int, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.scanEvents), len(t.targetEvents), len(t.findingEvents)
}

func TestEventDispatcher(t *testing.T) {
	dispatcher := NewEventDispatcher()
	listener := &TestListener{}

	// Test adding listeners
	dispatcher.AddScanListener(listener)
	dispatcher.AddTargetListener(listener)
	dispatcher.AddFindingListener(listener)

	// Verify listener counts
	counts := dispatcher.GetListenerCounts()
	if counts["scan"] != 1 || counts["target"] != 1 || counts["finding"] != 1 {
		t.Errorf("Expected 1 listener for each type, got %v", counts)
	}

	// Test firing scan events
	dispatcher.FireScanStarted("scan-1", map[string]interface{}{"test": "data"})
	dispatcher.FireScanUpdated("scan-1", map[string]interface{}{"progress": 50})
	dispatcher.FireScanCompleted("scan-1", map[string]interface{}{"results": "found"})

	// Test firing target events
	dispatcher.FireTargetStarted("target-1", map[string]interface{}{"url": "test.com"})
	dispatcher.FireTargetCompleted("target-1", map[string]interface{}{"status": "ok"})

	// Test firing finding events
	dispatcher.FireFindingStarted("finding-1", map[string]interface{}{"type": "vulnerability"})
	dispatcher.FireFindingCompleted("finding-1", map[string]interface{}{"severity": "high"})

	// Allow goroutines to complete
	time.Sleep(10 * time.Millisecond)

	// Verify events were received
	scanCount, targetCount, findingCount := listener.GetEventCounts()
	if scanCount != 3 {
		t.Errorf("Expected 3 scan events, got %d", scanCount)
	}
	if targetCount != 2 {
		t.Errorf("Expected 2 target events, got %d", targetCount)
	}
	if findingCount != 2 {
		t.Errorf("Expected 2 finding events, got %d", findingCount)
	}

	// Test removing listeners
	dispatcher.RemoveScanListener(listener)
	dispatcher.RemoveTargetListener(listener)
	dispatcher.RemoveFindingListener(listener)

	// Verify listeners removed
	counts = dispatcher.GetListenerCounts()
	if counts["scan"] != 0 || counts["target"] != 0 || counts["finding"] != 0 {
		t.Errorf("Expected 0 listeners after removal, got %v", counts)
	}
}

func TestEventTypes(t *testing.T) {
	// Test event type constants
	if ScanEventStarted != "started" {
		t.Errorf("Expected ScanEventStarted to be 'started', got %s", ScanEventStarted)
	}
	if TargetEventUpdated != "updated" {
		t.Errorf("Expected TargetEventUpdated to be 'updated', got %s", TargetEventUpdated)
	}
	if FindingEventFailed != "failed" {
		t.Errorf("Expected FindingEventFailed to be 'failed', got %s", FindingEventFailed)
	}
}

func TestConcurrentEventDispatch(t *testing.T) {
	dispatcher := NewEventDispatcher()
	listener1 := &TestListener{}
	listener2 := &TestListener{}

	// Add multiple listeners
	dispatcher.AddScanListener(listener1)
	dispatcher.AddScanListener(listener2)

	// Fire events concurrently
	var wg sync.WaitGroup
	numEvents := 10

	wg.Add(numEvents)
	for i := 0; i < numEvents; i++ {
		go func(id int) {
			defer wg.Done()
			dispatcher.FireScanStarted("concurrent-scan", map[string]interface{}{"id": id})
		}(i)
	}

	wg.Wait()
	time.Sleep(20 * time.Millisecond) // Allow goroutines to complete

	// Both listeners should receive all events
	count1, _, _ := listener1.GetEventCounts()
	count2, _, _ := listener2.GetEventCounts()

	if count1 != numEvents {
		t.Errorf("Listener1 expected %d events, got %d", numEvents, count1)
	}
	if count2 != numEvents {
		t.Errorf("Listener2 expected %d events, got %d", numEvents, count2)
	}
}