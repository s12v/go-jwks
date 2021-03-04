package jwks

import (
	"log"
)

type jwksLogger interface {
	Printf(format string, v ...interface{})
}

// This is necessary to work around go1.12 requirement
type defaultLogger struct{}

func (defaultLogger) Printf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

var logger jwksLogger = defaultLogger{}

func SetLogger(l jwksLogger) {
	logger = l
}
