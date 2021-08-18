package jwks

import (
	"log"
)

type logging interface {
	Printf(format string, v ...interface{})
}

type defaultLogger struct{}

func (defaultLogger) Printf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

var logger logging = defaultLogger{}

func SetLogger(l logging) {
	logger = l
}
