package jwks

import (
	"log"
)

type jwksLogger interface {
	Printf(format string, v ...interface{})
}

var logger jwksLogger = log.Default()

func SetLogger(l jwksLogger) {
	logger = l
}
