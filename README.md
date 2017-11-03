# cert-manage

**Note** This tool is still under its initial development. Expect things to break and change.

The state of [Certificate Authority](https://en.wikipedia.org/wiki/Certificate_authority) trust isn't great. Any system you buy will come pre-loaded with trust of 50+ CA's. This means that your connections (and privacy) are at risk if even one of them creates privacy-destructive certificates. Read up on the [background](#background) if you're interested.

Trust with another party needs to be earned, not defaulted. `cert-manage` is a tool to give users straightfoward control of their trusted [x509 Certificate](https://en.wikipedia.org/wiki/X.509) stores on their systems and applications.

## Usage

```
# List certificates trusted on your system (or app)
$ cert-manage -list
$ cert-manage -list -app chrome

# Trim down what CA's are trusted on your system
$ cert-manage -whitelist -file digicert.json
$ cert-manage -app chrome -whitelist -file digicert.json

# Backup and Restore the current trust
$ cert-manage -backup
$ cert-manage -restore [-file <path>]
```

## Install

There's no released versions yet, but to use `cert-manage` you can pull down the source code and build with `make build`. There are no external packages pulled in.

~~You can download prebuilt binaries [on the releases tab](https://github.com/adamdecaf/cert-manage/releases) or compile the source after a `go get` of the repo.~~

#### Platforms

| Platform | Version(s) |
|----|----|
| Alpine | 3.6 |
| Debian | 8, 9 |
| OSX/macOS | 10.11 |
| Ubuntu | 16.04, 17.04 |

#### Applications

TODO: These apps aren't _actually_ supported yet.

| Application | Version(s) | Supported Platforms |
|----|----|----|
| Google Chrome | All | Linux, OSX/macOS, Windows |
| Firefox | All | Linux, OSX/macOS, Windows |
| Java | 7,8 | Linux, OSX/macOS, Windows |

## Whitelists

TODO(adam): needs updates...

### Configuration

Whitelists are stored in json files. There is a basic structure to them which allows for multiple methods of whitelisting. The structure looks like:

```json
{
  "Fingerprints": {
    "Hex": [
      "050cf9fa95e40e9bddedaeda6961f6168c1279c4660172479cdd51ab03cea62c"
    ]
  }
}
```

**Fields**

- `Fingerprints.Hex`: The hex encoded fingerprint of the certificate

## Background

TODO(adam): more detail & better explained

- explain that users need choices and assurance in what they're trusting
- some CA's are better than others, some are really bad (negligent)

There have been numerous recent exploits in the wild surrounding CA's (Certificate Authorities) that don't understand the power they have on every system which trusts communications signed with their keys.

- Comodo
  - Invalid domains
    Comodo issued certs for invalid domains. In specific, `www.sb` which should not have been generated. It has since [been revoked](https://crt.sh/?id=34242572).
  - OCR to validate documents
    OCR is a process in which algorithms try to find and understand human/computer writing in digital documents. This process is far from perfect and should only be used as a means of creating faster processes prior to human validation steps. It was found that [OCR algorithms could lead to bogus (and fradulent)](https://bugzilla.mozilla.org/show_bug.cgi?id=1311713) certificates being generated.
- [CNNIC](https://blog.mozilla.org/security/2015/03/23/revoking-trust-in-one-cnnic-intermediate-certificate/)
- DigiCert
  - [Certificate with invalid dnsName issued from Baltimore intermediate](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/5bpr9yBgaYo)
- [DigiNotar](https://en.wikipedia.org/wiki/DigiNotar)
- [Equifax](https://www.consumerreports.org/privacy/what-consumers-need-to-know-about-the-equifax-data-breach/)
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

There have also been crazy modifications done by other software components/vendors, which don't relate to secure x509 communication.

- Savitech USB audio drivers [install a new root CA certificate](https://www.kb.cert.org/vuls/id/446847)

## Building / Developing

TODO(adam): these are wrong/out of date

You can build the sources with `make build`. You can build only a platform with something like `make osx`. Please check the `makefile` for more details.

You can test out a specific platform with commands like `make run platform=alpine-35 flags='-find'`. They're based on docker containers and I'm working to add support under there for all platforms.

## Related projects

- [chengr28/RevokeChinaCerts](https://github.com/chengr28/RevokeChinaCerts)
- [MSylvia/CertTrustSetter](https://github.com/MSylvia/CertTrustSetter)
- [ntkme/security-trust-settings-tools](https://github.com/ntkme/security-trust-settings-tools)
- [storborg/dotfiles paranoia.py](https://github.com/storborg/dotfiles/blob/master/scripts/paranoia.py)

## Related Documentation / Websites

- [CACert Wiki](http://wiki.cacert.org/CAcert)
- [Mozilla CA Incident Dashboard](https://wiki.mozilla.org/CA/Incident_Dashboard)
