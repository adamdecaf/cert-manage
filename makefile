.PHONY: build test

default: test

vet:
	go vet ./...

test: vet
	go test -v ./...
