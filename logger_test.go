package jwks

import (
	"fmt"
	"sync"
	"testing"
)

type recordingLogger struct {
	mu       sync.Mutex
	messages []string
}

func (l *recordingLogger) Printf(format string, v ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, fmt.Sprintf(format, v...))
}

// count tells how many times the message was logged. Goroutines left behind
// by other tests may log as well, so the messages are not simply counted.
func (l *recordingLogger) count(message string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, m := range l.messages {
		if m == message {
			n++
		}
	}
	return n
}

func TestSetLogger(t *testing.T) {
	t.Cleanup(func() { SetLogger(defaultLogger{}) })

	recorder := &recordingLogger{}
	SetLogger(recorder)
	logf("message %d", 1)
	if recorder.count("message 1") != 1 {
		t.Fatal("expected the message to be logged")
	}

	// nil turns logging off
	SetLogger(nil)
	logf("message %d", 2)

	// and the logger can be set again
	SetLogger(recorder)
	logf("message %d", 3)
	if recorder.count("message 2") != 0 || recorder.count("message 3") != 1 {
		t.Fatal("expected message 3 only")
	}
}

// The logger may be replaced while background goroutines are logging.
func TestSetLogger_Concurrent(t *testing.T) {
	t.Cleanup(func() { SetLogger(defaultLogger{}) })

	recorder := &recordingLogger{}
	SetLogger(recorder)

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				logf("message")
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		SetLogger(recorder)
	}
	wg.Wait()

	if n := recorder.count("message"); n != 4000 {
		t.Fatalf("expected 4000 messages, got %d", n)
	}
}
