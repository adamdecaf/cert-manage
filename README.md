# cert-manage

**Note** This tool is still under its initial development. Expect things to break and change.

Every computer connected to the internet today has a series of "certificate stores" contained within it. Those stores are crucial to encrypted communication everywhere. There's a problem however in that the state of these isn't great.

The underlying [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) technology leaves a lot lacking in terms of management, pro-active countermeasures and misuse. Any system you buy will come pre-loaded with trust of countless CA's, which means that your encrypted connections are at risk of eavesdropping even if only one CA creates privacy-destructive certificates. Read up on the [background](#background) if you're interested.

Trust with another party needs to be earned, not defaulted. `cert-manage` is a tool to give users straightforward control of their trusted [x509 Certificate](https://en.wikipedia.org/wiki/X.509) stores on their systems and applications.

## Install / Usage

Once there are released versions available you can download them from the "Releases" tab of this repository. If you wish to try cert-manage the best option is to pull down the source code and build it for yourself.

```
$ go get github.com/adamdecaf/cert-manage

# List certificates trusted on your system (or app)
$ cert-manage list
$ cert-manage list -app java
Certificate
  SHA1 Fingerprint - b3eac44776c9c81ceaf29d95b6cca0081b67ec9d
  SHA256 Fingerprint - 3a43e220fe7f3ea9653d1e21742eac2b75c20fd8980305bc502caf8c2d9b41a1
  SerialNumber: 246153180488710619953605749449532672687
  Subject: VeriSign, Inc., Class 2 Public Primary Certification Authority - G2
  Issuer: VeriSign, Inc., Class 2 Public Primary Certification Authority - G2
  NotBefore - 1998-05-18 00:00:00 +0000 UTC, NotAfter - 2028-08-01 23:59:59 +0000 UTC
  IsCA - false
...

# Trim down what CA's are trusted on your system
$ cert-manage whitelist -file digicert.json
$ cert-manage whitelist -app chrome -file digicert.json

# Backup and Restore the current trust
$ cert-manage backup
$ cert-manage restore [-file <path>]
```

## Features

`cert-manage` offers a few features currently: List, Whitelisting and Backup/Restore. These are explained as follows:

- [List](docs/features.md#list)
  - Show the certificates installed and trusted by a given certificate store. This is useful for an initial trust audit
- [Whitelist](docs/features.md#whitelisting)
  - Remove (or distrust) installed certificates. This will prevent good acting programs (and platforms) from making connections signed by organizations you don't trust.
- [Backup and Restore](docs/features.md#backup-and-restore)
  - Capture and revert the status of CA trust in a platform or application.

#### Support

`cert-manage` abstracts over the differences in Certificate stores for the following platforms:

| Level | Platforms(s) |
|----|----|
| Full Support | Linux (Alpine, Debian, Ubuntu) |
| Partial Support | Darwin/OSX, Windows |

Also, `cert-manage` abstracts over the following application's certificate stores across the supported platforms.

| Level | Application(s) |
|-----|-----|
| Full Support | None |
| Partial Support | Chrome, Firefox (Linux/OSX), Java |

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
- TunRootCA2
  - [Inclusion Request](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/wCZsVq7AtUY)
- [WoSign and WoTrus](https://wiki.mozilla.org/CA:WoSign_Issues)
- [Visa](https://groups.google.com/d/msg/mozilla.dev.security.policy/NNV3zvX43vE/rae9kNkWAgAJ)


## Building / Developing

I'm always looking for new contributors and anything from help with docs, bugfixes or new certificate store additions is gladly appreciated. If you're interested in contributing then pull down the source code and submit some PR's or join `##cert-manage` on the freenode irc network.

You can build the sources with `make build`. Run tests with `make test`. Integration tests require docker installed and can be ran via `make ci`.

## Related projects

- [chengr28/RevokeChinaCerts](https://github.com/chengr28/RevokeChinaCerts)
- [mkcert.org](https://mkcert.org/)
- [msylvia/CertTrustSetter](https://github.com/MSylvia/CertTrustSetter)
- [ntkme/security-trust-settings-tools](https://github.com/ntkme/security-trust-settings-tools)
- [storborg/dotfiles paranoia.py](https://github.com/storborg/dotfiles/blob/master/scripts/paranoia.py)

## Related Documentation / Websites

- [CACert Wiki](http://wiki.cacert.org/CAcert)
- [Mozilla CA Incident Dashboard](https://wiki.mozilla.org/CA/Incident_Dashboard)
- [mozilla.dev.security.policy](https://groups.google.com/forum/#!forum/mozilla.dev.security.policy)
- [TLS Working Group](https://datatracker.ietf.org/wg/tls/charter/)

## Other x509 Related Articles

- [How I tricked Symantec with a Fake Private Key](https://blog.hboeck.de/archives/888-How-I-tricked-Symantec-with-a-Fake-Private-Key.html)
