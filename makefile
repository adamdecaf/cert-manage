VERSION := $(shell grep -Eo '(\d\.\d\.\d)(-dev)?' main.go)
GOARCH ?= $(shell go env GOARCH)

.PHONY: build check test dist linux osx win

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -trimpath -o bin/cert-manage-linux-$(GOARCH) github.com/adamdecaf/cert-manage
linux_amd64:
	$(MAKE) linux GOARCH=amd64

osx:
	CGO_ENABLED=0 GOOS=darwin GOARCH=$(GOARCH) go build -trimpath -o bin/cert-manage-osx-$(GOARCH) github.com/adamdecaf/cert-manage
osx_amd64:
	$(MAKE) osx GOARCH=amd64

win:
	CGO_ENABLED=0 GOOS=windows GOARCH=$(GOARCH) go build -trimpath -o bin/cert-manage-$(GOARCH).exe github.com/adamdecaf/cert-manage
win_64:
	$(MAKE) win GOARCH=amd64

dist: linux osx win

deps:
	dep ensure -update

.PHONY: check
check:
	go vet ./...
	go test -count=1 -timeout 3m $(GOTEST_FLAGS) ./pkg/... .

generate:
	CGO_ENABLED=0 go run pkg/whitelist/blacklist_gen.go

test: check
	$(MAKE) linux
	go test -count=1 -timeout 5m ./test/

build: check
	go build -trimpath -o cert-manage github.com/adamdecaf/cert-manage
	@chmod +x cert-manage

mkrel: generate
	gothub release -u adamdecaf -r cert-manage -t $(VERSION) --name $(VERSION) --pre-release

upload:
	gothub upload -u adamdecaf -r cert-manage -t $(VERSION) --name "cert-manage-linux" --file bin/cert-manage-linux-$(GOARCH)
	gothub upload -u adamdecaf -r cert-manage -t $(VERSION) --name "cert-manage-osx" --file bin/cert-manage-osx-$(GOARCH)
	gothub upload -u adamdecaf -r cert-manage -t $(VERSION) --name "cert-manage.exe" --file bin/cert-manage-$(GOARCH).exe
