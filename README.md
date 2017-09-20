# cert-manage

**Note** This tool is still under its initial development. Expect things to break and change.

`cert-manage` is a tool to manage, and lint all [x509 Certificates](https://en.wikipedia.org/wiki/X.509) certificate stores on your machines. This tool many operating systems for desktops and servers along with many applications.


|  OS  | Version Range | System Store? | Applications |
|------|-----------|------|--------------|
| Windows | todo | todo | Firefox, Chrome, Microsoft Edge |
| OSX / macOS | todo | todo | Firefox, Chrome, Safari |
| Linux Desktops (Debian, Ubuntu) | todo | todo | Firefox, Chrome, golang |
| Linux Servers (Debian, Ubuntu) | todo | todo | golang |


## Features

`cert-manage` aims to help you with:

- removing improperly trusted root certs from applications and systems
- updating cert stores based on public verifiable data

## Install

You can download prebuilt binaries [on the releases tab](https://github.com/adamdecaf/cert-manage/releases) or compile the source after a `go get` of the repo.

## Whitelists

TODO(adam): needs updates...

### Configuration

Whitelists are stored in json files. There is a basic structure to them which allows for multiple methods of whitelisting. The structure looks like:

```json
{
  "Signatures": {
    "Hex": [
      "050cf9fa95e40e9bddedaeda6961f6168c1279c4660172479cdd51ab03cea62c"
    ]
  },
  "Issuers": [
    {
      "CommonName": "WoSign"
    }
  ],
  "Time": {
    "NotAfter": "2016-01-01 12:34:56"
  }
}
```

**Fields**

- `Signatures.Hex`: The hex encoded signature on the certificate.
- `Issuers.CommonName`: An exact match to the Issuer's CommonName on the certificate. (e.g. "Go Daddy")
- `Issuers.Organization`: An exact match to the Issuers's Organization field on the certificate.
- `Time.NotAfter`: The NotAfter field on the certificate. (Useful for only allowing certs with long expirations. e.g. 2030)


## Background

TODO(adam): more detail & better explained

- explain that users need choices and assurance in what they're trusting
- some CA's are better than others, some are really bad (negligent)

There have been numerous recent exploits in the wild surrounding CA's (Certificate Authorities) that don't understand the power they have on every machine which trusts communications signed with their keys.

- Comodo
  - Invalid domains
    Comodo issued certs for invalid domains. In specific, `www.sb` which should not have been generated. It has since [been revoked](https://crt.sh/?id=34242572).
  - OCR to validate documents
    OCR is a process in which algorithms try to find and understand human/computer writing in digital documents. This process is far from perfect and should only be used as a means of creating faster processes prior to human validation steps. It was found that [OCR algorithms could lead to bogus (and fradulent)](https://bugzilla.mozilla.org/show_bug.cgi?id=1311713) certificates being generated.
- [CNNIC](https://blog.mozilla.org/security/2015/03/23/revoking-trust-in-one-cnnic-intermediate-certificate/)
- DigiCert
  - [Certificate with invalid dnsName issued from Baltimore intermediate](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/5bpr9yBgaYo)
- [DigiNotar](https://en.wikipedia.org/wiki/DigiNotar)
- GlobalSign
  - [Accidental cross-signing intermediate certificate](https://downloads.globalsign.com/acton/fs/blocks/showLandingPage/a/2674/p/p-008f/t/page/fm/0)
- GoDaddy
  - [Improper Domain Validation](https://groups.google.com/forum/?hl=en#!msg/mozilla.dev.security.policy/Htujoyq-pO8/uRBcS2TmBQAJ)
- Government Root Certification Authority
  - [Does the US government operate a publicly trusted certificate authority?](https://https.cio.gov/certificates/#does-the-us-government-operate-a-publicly-trusted-certificate-authority?)
- Guang Dong Certificate Authority
  - [root inclusion request](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/kB2JrygK7Vk)
- IdenTrust
  - [Certificates issued with HTTPS OCSP responder URL](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/jSHuE-Oc7rY)
- Let's Encrypt
  - [CAA Checks](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/SrAhO4ye4G8)
  - [DNSSEC](https://groups.google.com/d/msg/mozilla.dev.security.policy/r9QM8tNqxx0/ZmnWwTXoAQAJ)
  - [Debian Weak Key](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/WL_-9pVhZf8)
- [PROCERT](https://wiki.mozilla.org/CA:PROCERT_Issues)
- StartCom
  - [StartEncrypt](https://www.computest.nl/blog/startencrypt-considered-harmful-today/)
  - [StartCom & Qihoo Incidents](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/TbDYE69YP8E)
  - [Re-inclusion request into Mozilla](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/hNOJJrN6WfE)
- [Symantec](https://wiki.mozilla.org/CA:Symantec_Issues)
- TunRootCA2
  - [Inclusion Request](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/wCZsVq7AtUY)
- [WoSign and WoTrus](https://wiki.mozilla.org/CA:WoSign_Issues)
- [Visa](https://groups.google.com/d/msg/mozilla.dev.security.policy/NNV3zvX43vE/rae9kNkWAgAJ)

## Building / Developing

TODO: these are wrong/out of date

You can build the sources with `make build`. You can build only a platform with something like `make osx`. Please check the `makefile` for more details.

You can test out a specific platform with commands like `make run platform=alpine-35 flags='-find'`. They're based on docker containers and I'm working to add support under there for all platforms.
