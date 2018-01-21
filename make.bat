:: Just run tests and build windows binary

go test ./...

set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -o bin/cert-manage-amd64.exe github.com/adamdecaf/cert-manage
