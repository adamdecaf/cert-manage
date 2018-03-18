# cert-manage

Every computer connected to the internet today has a series of "certificate stores" contained within it. These stores are crucial to encrypted communication everywhere, but their state often drifts between providers and can many times extend trust further than users expect.

The underlying [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) technology doesn't offer solutions for fine grained management, active countermeasures and misuse prevention for end-user machines. Any system you buy will come loaded with trust of countless CA's, which means that your encrypted connections are at risk of eavesdropping or misrepresentation if any CA creates privacy-destructive or nefarious certificates. Read up on the [background](#background) if you're interested.

Trust with another party needs to be earned, not defaulted. `cert-manage` is a tool to give users easier control of their trusted [x509 Certificate](https://en.wikipedia.org/wiki/X.509) stores on their systems and applications.

## Features

`cert-manage` offers a few features currently: List, Whitelisting and Backup/Restore. These are explained as follows:

- [Add](docs/basics.md#add)
  - Add certificates to a store
- [List](docs/basics.md#list)
  - Show the certificates installed and trusted by a given certificate store. This is useful for an initial trust audit
- [Whitelist](docs/whitelists.md#whitelisting)
  - Remove (or distrust) installed certificates. This will prevent good acting programs (and platforms) from making connections signed by organizations you don't trust.
- [Backup and Restore](docs/basics.md#backup-and-restore)
  - Capture and revert the status of CA trust in a platform or application.
- [Whitelist Generation](docs/whitelists.md#generating-whitelists)
  - Generate whitelists from browser history or flat files.

## Install / Usage

Download the [latest release](https://github.com/adamdecaf/cert-manage/releases) or build from source with `go get github.com/adamdecaf/cert-manage`

```
# List certificates trusted on your system (or app)
$ cert-manage list
$ cert-manage list -app java
Certificate
  SHA256 Fingerprint - 3a43e220fe7f3ea9653d1e21742eac2b75c20fd8980305bc502caf8c2d9b41a1
  SerialNumber: 246153180488710619953605749449532672687
  Subject: VeriSign, Inc., Class 2 Public Primary Certification Authority - G2
  Issuer: VeriSign, Inc., Class 2 Public Primary Certification Authority - G2
  NotBefore - 1998-05-18 00:00:00 +0000 UTC, NotAfter - 2028-08-01 23:59:59 +0000 UTC
  IsCA - false
...
$ cert-manage list -file example.crt
$ cert-manage list -url https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt

# Trim down what CA's are trusted on your system
$ cert-manage whitelist -file urls.yaml # or json
$ cert-manage whitelist -app chrome -file urls.yaml

# Backup and Restore the current trust
$ cert-manage backup
$ cert-manage restore [-file <path>]
```

## Platform / Application Support

`cert-manage` abstracts over the differences in Certificate stores for the following platforms:

| Level | Platforms(s) |
|----|----|
| Full Support | Linux (Alpine, Debian, Ubuntu) |
| Partial Support | Darwin/OSX, Windows |

Also, `cert-manage` abstracts over the following application's certificate stores across the supported platforms.

| Level | Application(s) |
|-----|-----|
| Full Support | Java |
| Partial Support | Chrome, Firefox, OpenSSL |

## Supporting Research

- [Analysis of the HTTPS Certificate Ecosystem](docs/papers/https-imc13.pdf) (2013)
   - "We investigate the trust relationships among root authorities, intermediate authorities, and the leaf certificates used by web servers, ultimately identifying and classifying more than **1,800 entities** that are able to issue certificates vouching for the identity of any website."
   - "Disturbingly, we find that the compromise of the private key used by one particular intermediate certificate would require 26% of HTTPS websites to immediately obtain new certificates."
- [CAge - Taming Certificate Authorities by Inferring Restricted Scopes](docs/papers/cage-fc13.pdf)
   - "We find that simple inference rules can reduce the attack surface by nearly a factor of ten without hindering 99% of CA activity over a 6 month period."
- [You Won't Be Needing These Any More: On Removing Unused Certicates From Trust Stores](docs/papers/on-removing-unused-certs.pdf)
   - "We found that of the 426 trusted root certificates, only 66 % were used to sign HTTPS certificates."

## Background

There have been numerous recent exploits in the wild surrounding CA's (Certificate Authorities) that don't understand the power they have on every system which trusts communications signed with their keys. Additionally distributors of certificate stores have started to become aware and demand stricter working requirements from CA's, but the power is not readily available in the users hands for them to make these decisions themselves.

Below is a short list of incidents over the past couple of years (2015-2017) from CA's either acting carelessly or maliciously.

- Blizzard / EA Origin
  - [Local CA](https://groups.google.com/forum/#!msg/mozilla.dev.security.policy/pk039T_wPrI/tGnFDFTnCQAJ) (clienttolocalhostonly.com and localblizzard.net)
    Blizzard and EA were running an HTTPS webserver on 127.0.0.1 (where the domains resolve) with a valid certificate. This implies that there's a private key bundled with the software which is considered a "key compromise" and requires revocation of the certificate.
    This issue is not itself bad, but allows an attacker to mitm the dns for either domain and be presented with a valid connection to end users.
- Comodo
  - Invalid domains
    Comodo issued certs for invalid domains. In specific, `www.sb` which should not have been generated. It has since [been revoked](https://crt.sh/?id=34242572).
  - OCR to validate documents
    OCR is a process in which algorithms try to find and understand human/computer writing in digital documents. This process is far from perfect and should only be used as a means of creating faster processes prior to human validation steps. It was found that [OCR algorithms could lead to bogus (and fraudulent)](https://bugzilla.mozilla.org/show_bug.cgi?id=1311713) certificates being generated.
- [CNNIC](https://blog.mozilla.org/security/2015/03/23/revoking-trust-in-one-cnnic-intermediate-certificate/)
- DigiCert
  - [Certificate with invalid dnsName issued from Baltimore intermediate](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/5bpr9yBgaYo)
- [DigiNotar](https://en.wikipedia.org/wiki/DigiNotar)
- DYMO
  - [Installs a Root CA Certificate](https://github.com/njh/dymo-root-ca-security-risk)
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
- Savitech USB audio drivers
  - [Installs a Root CA Certificate](https://www.kb.cert.org/vuls/id/446847)
- StartCom
  - [StartEncrypt](https://www.computest.nl/blog/startencrypt-considered-harmful-today/)
  - [StartCom & Qihoo Incidents](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/TbDYE69YP8E)
  - [Re-inclusion request into Mozilla](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/hNOJJrN6WfE)
- [Symantec](https://wiki.mozilla.org/CA:Symantec_Issues)
  - "I think there are [279 non-constrained TLS-capable issuing CAs that are not reported](https://bugzilla.mozilla.org/show_bug.cgi?id=1417771)."
  - [Known active and legacy root certificates](https://chromium.googlesource.com/chromium/src/+/master/net/data/ssl/symantec/README.md)
- [Trustico CEO emailing DigiCert 23k Private Keys](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/wxX4Yv0E3Mk)
- TunRootCA2
  - [Inclusion Request](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/wCZsVq7AtUY)
- [WoSign and WoTrus](https://wiki.mozilla.org/CA:WoSign_Issues)
- [Visa](https://groups.google.com/d/msg/mozilla.dev.security.policy/NNV3zvX43vE/rae9kNkWAgAJ)


## Developing / Contributing

I'm always looking for new contributors and anything from help with docs, bugfixes or new certificate store additions is gladly appreciated. If you're interested in contributing then pull down the source code and submit some PR's or join `##cert-manage` on the freenode irc network.

You can build the sources with `make build`. Run tests with `make test`. Currently we required Go 1.10.

Note: Many tests will run if docker is enabled/setup. To disable this run commands with `MOCKED=true` (e.g. `MOCKED=true make test`)

This project follows the [Google Code of Conduct](https://opensource.google.com/conduct/).

## Related projects

- [certpatrol](http://patrol.psyced.org/)
- [chengr28/RevokeChinaCerts](https://github.com/chengr28/RevokeChinaCerts)
- [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide#certificate-authorities)
- [kirei/catt](https://github.com/kirei/catt)
- [mkcert.org](https://mkcert.org/)
- [mozilla/tls-observatory](https://github.com/mozilla/tls-observatory)
- [msylvia/CertTrustSetter](https://github.com/MSylvia/CertTrustSetter)
- [nabla-c0d3/trust_stores_observatory](https://github.com/nabla-c0d3/trust_stores_observatory)
- [ntkme/security-trust-settings-tools](https://github.com/ntkme/security-trust-settings-tools)
- [sebdeckers/tls-keygen](https://gitlab.com/sebdeckers/tls-keygen)
- [storborg/dotfiles paranoia.py](https://github.com/storborg/dotfiles/blob/master/scripts/paranoia.py)
- [SSL Blacklist 4.0](http://www.codefromthe70s.org/sslblacklist.aspx)

## Related Articles and Documentation

- [SSL and the Future of Authenticity](https://moxie.org/blog/ssl-and-the-future-of-authenticity/)
- [Mozilla Certificate Policy](https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/)
- [Mozilla CA Incident Dashboard](https://wiki.mozilla.org/CA/Incident_Dashboard)
- [mozilla.dev.security.policy](https://groups.google.com/forum/#!forum/mozilla.dev.security.policy)
- [TLS Working Group](https://datatracker.ietf.org/wg/tls/charter/)
