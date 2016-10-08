# cert-manage

**Note** This tool is still under its initial development. Expect things to break and change.

`cert-manage` is a tool to manage certs across all cert stores on your machines. This tool many operating systems for desktops and servers along with many applications.

|  OS  | Version Range | System Store? | Applications |
|------|-----------|------|----|--------------|
| Windows | todo | todo | Firefox, Chrome, Microsoft Edge |
| OSX / macOS | todo | todo | Firefox, Chrome, Safari |
| Linux Desktops (Debian, Ubuntu) | todo | todo | Firefox, Chrome, golang |
| Linux Servers (Debian, Ubuntu) | todo | todo | golang |

## Install

## Building

You can build the sources with `make build`. You can build only a platform with something like `make osx`. Please check the `makefile` for more details.

You can test out a specific platform with the scripts under `./build/$platform/`. They're based on docker containers and I'm working to add support under there for all platforms.

## Background

There have been numerous recent exploits in the wild surrounding CA's (Certificate Authorities) that don't understand the power they have on every machine which trusts communications signed with their keys. Below are a few examples of recent exploits whose trust is still valid on most machines.

- https://www.computest.nl/blog/startencrypt-considered-harmful-today/
- https://wiki.mozilla.org/CA:WoSign_Issues
  - https://docs.google.com/document/d/1C6BlmbeQfn4a9zydVi2UvjBGv6szuSB4sMYUcVrR8vQ/preview
  - https://www.wosign.com/report/WoSign_Incident_Report_Update_07102016.pdf
- https://crt.sh/?id=34242572 (Comodo cert for `www.sb`)
