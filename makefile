VERSION := $(shell grep -Eo '(\d\.\d\.\d)(-dev)?' main.go)

.PHONY: build check test

linux: linux_amd64
linux_amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/cert-manage-linux-amd64 github.com/adamdecaf/cert-manage

osx: osx_amd64
osx_amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/cert-manage-osx-amd64 github.com/adamdecaf/cert-manage

win: win_64
win_64:
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -o bin/cert-manage-amd64.exe github.com/adamdecaf/cert-manage

dist: build linux osx win

deps:
	dep ensure -update

.PHONY: check
check:
ifeq ($(OS),Windows_NT)
	go vet ./...
	go test ./...
else
	# @wget -O lint-project.sh https://raw.githubusercontent.com/moov-io/infra/master/go/lint-project.sh
	# @chmod +x ./lint-project.sh
	# GOLANGCI_ALLOW_PRINT=yes COVER_THRESHOLD=50.0 ./lint-project.sh
	go vet ./...
	go test ./...
endif

generate:
	CGO_ENABLED=0 go run pkg/whitelist/blacklist_gen.go

test: check dist
	CGO_ENABLED=0 go test ./...
	INTEGRATION=yes go test ./... -run TestIntegration__ -count 1

build: check
	go build -o cert-manage github.com/adamdecaf/cert-manage
	@chmod +x cert-manage

mkrel: generate
	gothub release -u adamdecaf -r cert-manage -t $(VERSION) --name $(VERSION) --pre-release

upload:
	gothub upload -u adamdecaf -r cert-manage -t $(VERSION) --name "cert-manage-linux" --file bin/cert-manage-linux-amd64
	gothub upload -u adamdecaf -r cert-manage -t $(VERSION) --name "cert-manage-osx" --file bin/cert-manage-osx-amd64
	gothub upload -u adamdecaf -r cert-manage -t $(VERSION) --name "cert-manage.exe" --file bin/cert-manage-amd64.exe
