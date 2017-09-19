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

- removing insecure root certs from applications and systems
- updating cert stores based on public verifiable data
- linting certificates to ensure spec compatability

## Install

You can download prebuilt binaries [on the releases tab](https://github.com/adamdecaf/cert-manage/releases) or compile the source after a `go get` of the repo.

## Background

There have been numerous recent exploits in the wild surrounding CA's (Certificate Authorities) that don't understand the power they have on every machine which trusts communications signed with their keys. I've setup some [links and details](docs/why/).

### Comodo Issues

#### Invalid domains

Comodo issued certs for invalid domains. In specific, `www.sb` which should not have been generated. It has since [been revoked](https://crt.sh/?id=34242572).

#### OCR to validate documents

OCR is a process in which algorithms try to find and understand human/computer writing in digital documents. This process is far from perfect and should only be used as a means of creating faster processes prior to human validation steps. It was found that [OCR algorithms could lead to bogus (and fradulent)](https://bugzilla.mozilla.org/show_bug.cgi?id=1311713) certificates being generated.

### GlobalSign Issues

#### Accidental cross-signing

GlobalSign accidently revoked an intermediate certificates in a policy error.

[Customer release](https://downloads.globalsign.com/acton/fs/blocks/showLandingPage/a/2674/p/p-008f/t/page/fm/0)

<details>
<summary>**Full Release** (This is a copy incase that link dies.)</summary>
> Dear Valued GlobalSign Customer,

> As most of you are aware, we are experiencing an internal process issue (details below) that is impacting your business. While we have identified the root-cause, we deeply apologize for the problems this is causing you and wanted to ensure you that we are actively resolving the issue.

> GlobalSign manages several root certificates and for compatibility and browser ubiquity reasons provides several cross-certificates between those roots to maximize the effectiveness across a variety of platforms.  As part of a planned exercise to remove some of those links, a cross-certificate linking two roots together was revoked.  CRL responses had been operational for 1 week, however an unexpected consequence of providing OCSP responses became apparent this morning, in that some browsers incorrectly inferred that the cross-signed root had revoked intermediates, which was not the case.

> GlobalSign has since removed the cross-certificate from the OCSP database and cleared all caches. However, the global nature of CDNs and effectiveness of caching continued to push some of those responses out as far as end users.  End users cannot always easily clear their caches, either through lack of knowledge or lack of permission.  New users (visitors) are not affected as they will now receive good responses.

> The problem will correct itself in 4 days as the cached responses expire, which we know is not ideal. However, in the meantime, GlobalSign will be providing an alternative issuing CA for customers to use instead, issued by a different root which was not affected by the cross that was revoked, but offering the same ubiquity and does not require to reissue the certificate itself.

> We are currently working on the detailed instructions to help you resolve the issue and will communicate those instruction to you shortly.

> Thank you for your patience.

> Lila Kee
> Chief Product Officer
> GMO GlobalSign

> US +1 603-570-7060 | UK +44 1622 766 766 | EU +32 16 89 1900
> www.globalsign.com/en


- [CNNIC](https://blog.mozilla.org/security/2015/03/23/revoking-trust-in-one-cnnic-intermediate-certificate/)
- [DigiNotar](https://en.wikipedia.org/wiki/DigiNotar)
- [Globalsign](globalsign.md)
- [GoDaddy](https://groups.google.com/forum/?hl=en#!msg/mozilla.dev.security.policy/Htujoyq-pO8/uRBcS2TmBQAJ)
- [Government Root Cert Authority](government-root-cert-authority.md)
- [Startcom](startcom.md)
- [Symantec](symantec.md)
- [Wosign](wosign.md)
</details>

### Government Root Certification Authority

My phone has a "Government Root Certification Authority" CA installed

http://grca.nat.gov.tw/GRCAeng/htdocs/index.html  <-- Is it this cert?, todo: check

https://www.idmanagement.gov/IDM/s/article_content_old?tag=a0Gt0000000SfwP
https://https.cio.gov/certificates/#does-the-us-government-operate-a-publicly-trusted-certificate-authority?

### StartCom Issues

#### StartEncrypt

StartEncrypt was created out of jealousy of the success from LetsEncrypt.

Quickly after launch, it was discovered that StartEncrypt had a severe vulnerability in that certificates would be issues for domains not under the requestor's control.

> Recently, one of our hackers (Thijs Alkemade) found a critical vulnerability in StartCom’s new StartEncrypt tool, that allows an attacker to gain valid SSL certificates for domains he does not control.

[News Link](https://www.computest.nl/blog/startencrypt-considered-harmful-today/)

#### StartCom & Qihoo Incidents

Mozilla had a posting where [some issues with StartCom were found](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/TbDYE69YP8E).

### Symantec Issues

#### 2017-01-23 108 Certificates

Link: http://arstechnica.com/security/2017/01/already-on-probation-symantec-issues-more-illegit-https-certificates/

The CA's impacted: Symantec Trust Network, GeoTrust Inc., and Thawte Inc

#### Invalid domains issued certificates for

Link: https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/fyJ3EK2YOP8

### WoSign Issues

#### Mozilla Multi-Issue

WoSign was recently suspended from Mozilla's Firefox browser after numerous issues many of which are in direct violation of the CA forum. I've included linkes below.

Links
- [Mozilla discussion](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/BV5XyFJLnQM)
- [Mozilla Wiki page of all issues](https://wiki.mozilla.org/CA:WoSign_Issues)
- [WoSign Response part 1](https://docs.google.com/document/d/1C6BlmbeQfn4a9zydVi2UvjBGv6szuSB4sMYUcVrR8vQ/preview)
- [WoSign Incidnet report](https://www.wosign.com/report/WoSign_Incident_Report_Update_07102016.pdf)
- [WoSign renames to WoTrus](https://www.wosign.com/english/News/English_name_change_to_WoTrus_2017.htm)
