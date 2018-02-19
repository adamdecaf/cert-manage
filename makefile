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
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/cert-manage-amd64.exe github.com/adamdecaf/cert-manage

dist: build linux osx win

deps:
	dep ensure -update

check:
	go vet ./...
	go fmt ./...

test: check dist
	go test ./...
	CGO_ENABLED=0 INTEGRATION=yes go test ./... -run TestIntegration__ -count 1

build: check
	go build -o cert-manage github.com/adamdecaf/cert-manage
	@chmod +x cert-manage

mkrel:
	gothub release -u adamdecaf -r cert-manage -t $(VERSION) --name $(VERSION) --pre-release

upload:
	gothub upload -u adamdecaf -r cert-manage -t $(VERSION) --name "cert-manage-linux" --file bin/cert-manage-linux-amd64
	gothub upload -u adamdecaf -r cert-manage -t $(VERSION) --name "cert-manage-osx" --file bin/cert-manage-osx-amd64
	gothub upload -u adamdecaf -r cert-manage -t $(VERSION) --name "cert-manage.exe" --file bin/cert-manage-amd64.exe
