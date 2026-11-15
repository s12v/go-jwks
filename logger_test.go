package jwks

import (
	"fmt"
	"log"
	"strings"
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

	// nil turns logging off: nothing goes to the standard logger either
	standard := &lockedBuffer{}
	original := log.Writer()
	log.SetOutput(standard)
	t.Cleanup(func() { log.SetOutput(original) })

	SetLogger(nil)
	logf("message %d", 2)
	if strings.Contains(standard.String(), "message 2") {
		t.Fatal("expected no output with a nil logger")
	}

	// the logger can be set again, also to the standard one
	SetLogger(recorder)
	logf("message %d", 3)
	if recorder.count("message 2") != 0 || recorder.count("message 3") != 1 {
		t.Fatal("expected message 3 only")
	}
	SetLogger(log.Default())
	logf("message %d", 4)
	if !strings.Contains(standard.String(), "message 4") {
		t.Fatal("expected the message in the standard log")
	}
}

type lockedBuffer struct {
	mu   sync.Mutex
	data strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.String()
}

type panickingLogger struct{}

func (panickingLogger) Printf(format string, v ...interface{}) {
	panic("boom")
}

// A broken logger must not take the application down: messages are logged
// from goroutines where it could not recover the panic.
func TestSetLogger_BrokenLogger(t *testing.T) {
	t.Cleanup(func() { SetLogger(defaultLogger{}) })

	SetLogger(panickingLogger{})
	logf("message")

	// a nil pointer is not a nil logger
	var none *recordingLogger
	SetLogger(none)
	logf("message")
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
	other := &recordingLogger{}
	for i := 0; i < 1000; i++ {
		SetLogger(other)
		SetLogger(recorder)
	}
	wg.Wait()

	// each message went to one of the two loggers
	if n := recorder.count("message") + other.count("message"); n != 4000 {
		t.Fatalf("expected 4000 messages, got %d", n)
	}
}
