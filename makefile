.PHONY: build check

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

check:
	go vet ./...
	go fmt ./...

test:
	./build/osx/test-prep.sh
	go test -v ./...
	go test -v github.com/adamdecaf/cert-manage/tools/_x509

ci: dist test
	./build/test.sh

build: check
	go build -o cert-manage github.com/adamdecaf/cert-manage
	@chmod +x cert-manage
