# cert-manage

**Note** This tool is still under its initial development. Expect things to break and change.

`cert-manage` is a tool to manage certs across all cert stores on your machines. This tool many operating systems for desktops and servers along with many applications.

|  OS  | Version Range | System Store? | Applications |
|------|-----------|------|----|--------------|
| Windows | todo | todo | Firefox, Chrome, Microsoft Edge |
| OSX / macOS | todo | todo | Firefox, Chrome, Safari |
| Linux Desktops (Debian, Ubuntu) | todo | todo | Firefox, Chrome, golang |
| Linux Servers (Debian, Ubuntu) | todo | todo | golang |

## Background

There have been numerous recent exploits in the wild surrounding CA's (Certificate Authorities) that don't understand the power they have on every machine which trusts communications signed with their keys. Below are a few examples of recent exploits whose trust is still valid on most machines.

- https://www.computest.nl/blog/startencrypt-considered-harmful-today/
- https://wiki.mozilla.org/CA:WoSign_Issues
  - https://docs.google.com/document/d/1C6BlmbeQfn4a9zydVi2UvjBGv6szuSB4sMYUcVrR8vQ/preview
