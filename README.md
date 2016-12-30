# cert-manage

**Note** This tool is still under its initial development. Expect things to break and change.

`cert-manage` is a tool to manage certs across all cert stores on your machines. This tool many operating systems for desktops and servers along with many applications.

|  OS  | Version Range | System Store? | Applications |
|------|-----------|------|----|--------------|
| Windows | todo | todo | Firefox, Chrome, Microsoft Edge |
| OSX / macOS | todo | todo | Firefox, Chrome, Safari |
| Linux Desktops (Debian, Ubuntu) | todo | todo | Firefox, Chrome, golang |
| Linux Servers (Debian, Ubuntu) | todo | todo | golang |

## Getting Started

#### Install

You can download prebuilt binaries [on the releases tab](https://github.com/adamdecaf/cert-manage/releases) or compile the source after a `go get` of the repo.

#### Configuration

Whitelists are stored in json files. There is a basic structure to them which allows for multiple methods of whitelisting. The structure looks like:

```json
{
    "Signatures": {
        "Hex": [""]
    },
    "Issuers": [
        {
            "CommonName": "",
            "Organization": ""
        }
    ],
    "Time": {
        "NotAfter": ""
    }
}
```

**Fields**

`Signatures.Hex`: The hex encoded signature on the certificate.
`Issuers.CommonName`: An exact match to the Issuer's CommonName on the certificate. (e.g. "Go Daddy")
`Issuers.Organization`: An exact match to the Issuers's Organization field on the certificate.
`Time.NotAfter`: The NotAfter field on the certificate. (Useful for only allowing certs with long expirations. e.g. 2030)

## Developing

#### Building

You can build the sources with `make build`. You can build only a platform with something like `make osx`. Please check the `makefile` for more details.

You can test out a specific platform with commands like `make run platform=alpine-35 flags='-find'`. They're based on docker containers and I'm working to add support under there for all platforms.

## Background

There have been numerous recent exploits in the wild surrounding CA's (Certificate Authorities) that don't understand the power they have on every machine which trusts communications signed with their keys. I've setup some [links and details](docs/why/).
