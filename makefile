.PHONY: build test whitelists

default: test

vet:
	go tool vet .

linux: linux_amd64
linux_amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o bin/cert-manage-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o bin/gen-whitelist-linux-amd64 ./gen/

osx: osx_amd64
osx_amd64:
	GOOS=darwin GOARCH=amd64 go build -o bin/cert-manage-osx-amd64 .
	GOOS=darwin GOARCH=amd64 go build -o bin/gen-whitelist-osx-amd64 ./gen/

win: win_32 win_64
win_32:
	CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -o bin/cert-manage-386.exe .
	CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -o bin/gen-whitelist-386.exe ./gen/
win_64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/cert-manage-amd64.exe .
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/gen-whitelist-amd64.exe ./gen/

run:
	@cp ./bin/cert-manage-linux-amd64 ./build/$(platform)/cert-manage
	@cd ./build/$(platform) && docker build -t cert-manage-$(platform):latest . > run.log
	@docker run -it cert-manage-$(platform):latest $(flags)


build: vet linux osx win

test: build
	go test -v ./...

whitelists:
	./bin/gen-whitelists.sh
