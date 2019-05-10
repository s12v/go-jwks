.PHONY: all
all: clean test

clean:
	rm -rf ./bin || true

test:
	go test -v ./... -coverprofile=coverage.txt -covermode=atomic
