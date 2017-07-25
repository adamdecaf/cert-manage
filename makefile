.PHONY: build test

default: test

vet:
	gometalinter . | sort

test: vet
	go test -v ./...
