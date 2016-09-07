build:
	go tool vet .

# OSX build
	GOOS=darwin GOARCH=386 go build -o cert-manage-osx .

# Linux build
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o cert-manage-linux .

# Windows build
	CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -o cert-manage-win .

test: build
	go test -v ./...
