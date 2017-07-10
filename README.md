# cert-manage

**Note** This tool is still under its initial development. Expect things to break and change.

`cert-manage` is a tool to manage, and lint [x509 Certificates](https://en.wikipedia.org/wiki/X.509) all certificate stores on your machines. This tool many operating systems for desktops and servers along with many applications.


|  OS  | Version Range | System Store? | Applications |
|------|-----------|------|--------------|
| Windows | todo | todo | Firefox, Chrome, Microsoft Edge |
| OSX / macOS | todo | todo | Firefox, Chrome, Safari |
| Linux Desktops (Debian, Ubuntu) | todo | todo | Firefox, Chrome, golang |
| Linux Servers (Debian, Ubuntu) | todo | todo | golang |


## Features

`cert-manage` aims to help you with:

- removing insecure root certs from applications and systems
- updating cert stores based on public verifiable data
- linting certificates to ensure spec compatability

## Install

You can download prebuilt binaries [on the releases tab](https://github.com/adamdecaf/cert-manage/releases) or compile the source after a `go get` of the repo.

## Background

There have been numerous recent exploits in the wild surrounding CA's (Certificate Authorities) that don't understand the power they have on every machine which trusts communications signed with their keys. I've setup some [links and details](docs/why/).
