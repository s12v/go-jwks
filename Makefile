.PHONY: all clean test vet

all: clean vet test

clean:
	rm -f coverage.txt

vet:
	go vet ./...

test:
	go test -race -v ./... -coverprofile=coverage.txt -covermode=atomic
