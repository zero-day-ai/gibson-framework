package model

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanEvent(t *testing.T) {
	uu := map[string]struct {
		eventType ScanEventType
		data      map[string]interface{}
		wantErr   bool
	}{
		"started_event": {
			eventType: ScanEventStarted,
			data:      map[string]interface{}{"target": "test-target"},
		},
		"updated_event": {
			eventType: ScanEventUpdated,
			data:      map[string]interface{}{"progress": 50},
		},
		"completed_event": {
			eventType: ScanEventCompleted,
			data:      map[string]interface{}{"findings": 5},
		},
		"failed_event": {
			eventType: ScanEventFailed,
			data:      map[string]interface{}{"reason": "timeout"},
			wantErr:   true,
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			event := &ScanEvent{
				ID:        "test-" + k,
				Type:      u.eventType,
				Timestamp: time.Now(),
				Data:      u.data,
			}

			if u.wantErr {
				event.Error = assert.AnError
			}

			assert.Equal(t, "test-"+k, event.ID)
			assert.Equal(t, u.eventType, event.Type)
			assert.Equal(t, u.data, event.Data)
			assert.NotZero(t, event.Timestamp)

			if u.wantErr {
				assert.Error(t, event.Error)
			} else {
				assert.Nil(t, event.Error)
			}
		})
	}
}

func TestTargetEvent(t *testing.T) {
	uu := map[string]struct {
		eventType TargetEventType
		data      map[string]interface{}
	}{
		"target_started": {
			eventType: TargetEventStarted,
			data:      map[string]interface{}{"name": "api-server"},
		},
		"target_updated": {
			eventType: TargetEventUpdated,
			data:      map[string]interface{}{"status": "scanning"},
		},
		"target_completed": {
			eventType: TargetEventCompleted,
			data:      map[string]interface{}{"result": "success"},
		},
		"target_failed": {
			eventType: TargetEventFailed,
			data:      map[string]interface{}{"error": "connection refused"},
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			event := &TargetEvent{
				ID:        "target-" + k,
				Type:      u.eventType,
				Timestamp: time.Now(),
				Data:      u.data,
			}

			assert.Equal(t, "target-"+k, event.ID)
			assert.Equal(t, u.eventType, event.Type)
			assert.Equal(t, u.data, event.Data)
			assert.NotZero(t, event.Timestamp)
		})
	}
}

func TestFindingEvent(t *testing.T) {
	uu := map[string]struct {
		eventType FindingEventType
		data      map[string]interface{}
	}{
		"finding_started": {
			eventType: FindingEventStarted,
			data:      map[string]interface{}{"type": "sql-injection"},
		},
		"finding_updated": {
			eventType: FindingEventUpdated,
			data:      map[string]interface{}{"severity": "high"},
		},
		"finding_completed": {
			eventType: FindingEventCompleted,
			data:      map[string]interface{}{"confirmed": true},
		},
		"finding_failed": {
			eventType: FindingEventFailed,
			data:      map[string]interface{}{"reason": "false positive"},
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			event := &FindingEvent{
				ID:        "finding-" + k,
				Type:      u.eventType,
				Timestamp: time.Now(),
				Data:      u.data,
			}

			assert.Equal(t, "finding-"+k, event.ID)
			assert.Equal(t, u.eventType, event.Type)
			assert.Equal(t, u.data, event.Data)
			assert.NotZero(t, event.Timestamp)
		})
	}
}

// MockScanEventListener implements ScanEventListener for testing
type MockScanEventListener struct {
	StartedEvents   []*ScanEvent
	UpdatedEvents   []*ScanEvent
	CompletedEvents []*ScanEvent
	FailedEvents    []*ScanEvent
	mu              sync.RWMutex
}

func (l *MockScanEventListener) ScanStarted(event *ScanEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.StartedEvents = append(l.StartedEvents, event)
}

func (l *MockScanEventListener) ScanUpdated(event *ScanEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.UpdatedEvents = append(l.UpdatedEvents, event)
}

func (l *MockScanEventListener) ScanCompleted(event *ScanEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.CompletedEvents = append(l.CompletedEvents, event)
}

func (l *MockScanEventListener) ScanFailed(event *ScanEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.FailedEvents = append(l.FailedEvents, event)
}

func (l *MockScanEventListener) GetCounts() (started, updated, completed, failed int) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.StartedEvents), len(l.UpdatedEvents), len(l.CompletedEvents), len(l.FailedEvents)
}

func TestScanEventListener(t *testing.T) {
	listener := &MockScanEventListener{}

	// Test interface compliance
	var _ ScanEventListener = listener

	// Test event handling
	startedEvent := &ScanEvent{
		ID:        "scan-1",
		Type:      ScanEventStarted,
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"target": "test"},
	}

	updatedEvent := &ScanEvent{
		ID:        "scan-1",
		Type:      ScanEventUpdated,
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"progress": 50},
	}

	completedEvent := &ScanEvent{
		ID:        "scan-1",
		Type:      ScanEventCompleted,
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"findings": 3},
	}

	failedEvent := &ScanEvent{
		ID:        "scan-2",
		Type:      ScanEventFailed,
		Timestamp: time.Now(),
		Error:     assert.AnError,
	}

	// Send events
	listener.ScanStarted(startedEvent)
	listener.ScanUpdated(updatedEvent)
	listener.ScanCompleted(completedEvent)
	listener.ScanFailed(failedEvent)

	// Verify events were received
	started, updated, completed, failed := listener.GetCounts()
	assert.Equal(t, 1, started)
	assert.Equal(t, 1, updated)
	assert.Equal(t, 1, completed)
	assert.Equal(t, 1, failed)

	// Verify event details
	require.Len(t, listener.StartedEvents, 1)
	assert.Equal(t, "scan-1", listener.StartedEvents[0].ID)
	assert.Equal(t, ScanEventStarted, listener.StartedEvents[0].Type)

	require.Len(t, listener.FailedEvents, 1)
	assert.Equal(t, "scan-2", listener.FailedEvents[0].ID)
	assert.Error(t, listener.FailedEvents[0].Error)
}

func TestConcurrentEventHandling(t *testing.T) {
	t.Parallel()

	listener := &MockScanEventListener{}
	var wg sync.WaitGroup

	numGoroutines := 10
	eventsPerGoroutine := 5

	// Send events concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				event := &ScanEvent{
					ID:        time.Now().Format("2006-01-02T15:04:05.999999999Z07:00") + "-" + string(rune('a'+goroutineID)) + "-" + string(rune('0'+j)),
					Type:      ScanEventStarted,
					Timestamp: time.Now(),
					Data:      map[string]interface{}{"goroutine": goroutineID, "event": j},
				}
				listener.ScanStarted(event)
			}
		}(i)
	}

	wg.Wait()

	// Verify all events were received
	started, _, _, _ := listener.GetCounts()
	expectedTotal := numGoroutines * eventsPerGoroutine
	assert.Equal(t, expectedTotal, started)
}

func TestEventTimestamps(t *testing.T) {
	start := time.Now()

	event1 := &ScanEvent{
		ID:        "test-1",
		Type:      ScanEventStarted,
		Timestamp: time.Now(),
	}

	time.Sleep(1 * time.Millisecond) // Small delay to ensure different timestamps

	event2 := &ScanEvent{
		ID:        "test-2",
		Type:      ScanEventUpdated,
		Timestamp: time.Now(),
	}

	end := time.Now()

	// Verify timestamps are within expected range
	assert.True(t, event1.Timestamp.After(start) || event1.Timestamp.Equal(start))
	assert.True(t, event1.Timestamp.Before(end) || event1.Timestamp.Equal(end))

	assert.True(t, event2.Timestamp.After(start) || event2.Timestamp.Equal(start))
	assert.True(t, event2.Timestamp.Before(end) || event2.Timestamp.Equal(end))

	// Verify event2 timestamp is after event1 timestamp
	assert.True(t, event2.Timestamp.After(event1.Timestamp) || event2.Timestamp.Equal(event1.Timestamp))
}