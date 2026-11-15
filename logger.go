package jwks

import (
	"log"
	"sync/atomic"
)

type jwksLogger interface {
	Printf(format string, v ...interface{})
}

// This is necessary to work around go1.12 requirement
type defaultLogger struct{}

func (defaultLogger) Printf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

// The logger is read from background goroutines, so it cannot be a plain
// variable: SetLogger may be called while they run.
var logger atomic.Pointer[jwksLogger]

// SetLogger sets the logger for all clients and sources. The default one
// uses the standard log package; nil turns logging off. It can be called at
// any time.
func SetLogger(l jwksLogger) {
	logger.Store(&l)
}

func logf(format string, v ...interface{}) {
	// A logger must not be able to take the client down. Messages are
	// logged from goroutines of this package, where a panic (of a broken
	// logger, or of a nil pointer passed to SetLogger as a logger) could
	// not be recovered by the application.
	defer func() { _ = recover() }()

	l := logger.Load()
	if l == nil {
		defaultLogger{}.Printf(format, v...)
		return
	}
	if *l != nil {
		(*l).Printf(format, v...)
	}
}
