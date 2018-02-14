## List

The cli sub-command `list` will output a list of certificates installed (and trusted) in the certificate store. This option defaults to the platform (Linux, OSX, or Windows), but can be switched to an application via the `-app` flag.

Show certificates installed in the platform:

```
$ ./cert-manage list
Certificate
  SHA1 Fingerprint - eab040689a0d805b5d6fd654fc168cff00b78be3
  SHA256 Fingerprint - 1a5174980a294a528a110726d5855650266c48d9883bea692b67b6d726da98c5
  SerialNumber: 26471149583208131559647911801012699958
  Subject: The USERTRUST Network
  Issuer: AddTrust AB, AddTrust External TTP Network
  NotBefore - 2000-05-30 10:48:38 +0000 UTC, NotAfter - 2020-05-30 10:48:38 +0000 UTC
  IsCA - true
  CRLDistributionPoints
    http://crl.usertrust.com/AddTrustExternalCARoot.crl
...
```

Show certificates installed for an application

```
$ ./cert-manage list -app firefox
Certificate
  SHA1 Fingerprint - eab040689a0d805b5d6fd654fc168cff00b78be3
  SHA256 Fingerprint - 1a5174980a294a528a110726d5855650266c48d9883bea692b67b6d726da98c5
  SerialNumber: 26471149583208131559647911801012699958
  Subject: The USERTRUST Network
  Issuer: AddTrust AB, AddTrust External TTP Network
  NotBefore - 2000-05-30 10:48:38 +0000 UTC, NotAfter - 2020-05-30 10:48:38 +0000 UTC
  IsCA - true
  CRLDistributionPoints
    http://crl.usertrust.com/AddTrustExternalCARoot.crl
...
```

Note: You can specify `-format table` to output all details of each certificate, but the result won't be in a table layout.

```
$ cert-manage list -app firefox -format table
Subject                                             Issuer                                                       Public Key Algorithm SHA256 Fingerprint Not Before Not After
AlphaSSL CA - SHA256 - G2                           GlobalSign Root CA                                           RSA                  ee793643199474ed   2014-02-20 2024-02-20
Amazon                                              Amazon Root CA 1                                             RSA                  f55f9ffcb83c7345   2015-10-22 2025-10-19
Amazon Root CA 1                                    Starfield Services Root Certificate Authority - G2           RSA                  87dcd4dc74640a32   2015-05-25 2037-12-31
...
```

If openssl is installed you can output certificates in that format (via `-format openssl`).

```
$ cert-manage list -app firefox -format openssl
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            f0:1d:4b:ee:7b:7c:a3:7b:3c:05:66:ac:05:97:24:58
        Signature Algorithm: sha384WithRSAEncryption
        Issuer: C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA Certification Authority
        Validity
            Not Before: May 18 00:00:00 2015 GMT
            Not After : May 17 23:59:59 2025 GMT
        Subject: C=US, ST=TX, L=Houston, O=cPanel, Inc., CN=cPanel, Inc. Certification Authority
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
            RSA Public Key: (2048 bit)
                Modulus (2048 bit):
                    00:8b:5e:01:56:b9:ec:6b:11:ef:48:e9:43:9e:9b:
                    ...
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Authority Key Identifier:
                keyid:BB:AF:7E:02:3D:FA:A6:F1:3C:84:8E:AD:EE:38:98:EC:D9:32:32:D4

            X509v3 Subject Key Identifier:
                7E:03:5A:65:41:6B:A7:7E:0A:E1:B8:9D:08:EA:1D:8E:1D:6A:C7:65
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Certificate Policies:
                Policy: 1.3.6.1.4.1.6449.1.2.2.52
                Policy: 2.23.140.1.2.1

            X509v3 CRL Distribution Points:
                URI:http://crl.comodoca.com/COMODORSACertificationAuthority.crl

            Authority Information Access:
                CA Issuers - URI:http://crt.comodoca.com/COMODORSAAddTrustCA.crt
                OCSP - URI:http://ocsp.comodoca.com

    Signature Algorithm: sha384WithRSAEncryption
        10:9f:a0:60:08:81:74:a1:a0:84:78:60:4c:39:39:da:64:77:
        ...
```

### TLS obsvervatory

`cert-manage` supports `-format observatory` which outputs certificates in a format supported by [nabla-c0d3/trust_stores_observatory](https://github.com/nabla-c0d3/trust_stores_observatory).

```
$ ./cert-manage list -format observatory -app chrome
platform: Darwin (OSX)
version: 10.13.3
url: ""
date_fetched: 2018-02-13
trusted_certificates_count: 176
trusted_certificates:
- subject_name: AffirmTrust
  fingerprint: 0376ab1d54c5f9803ce4b2e201a0ee7eef7b57b636e8a93c9b8d4860c96f5fa7
...
```

### Web

`cert-manage` can present certificates on a local web page with `-ui web` passed to any command.

```
$ cert-manage list -app java -ui web
```

## Backup and Restore

It's important to be able to rollback changes to your certificate store. These changes can be dangerous if done incorrectly as many websites you visit might partially quit loading.

To capture a backup:

```
$ cert-manage backup
Backup completed successfully

$ cert-manage backup -app java
Backup completed successfully
```

Backups can be used as restore points.

```
# Restore from the latest backup
$ cert-manage restore -app chrome
```
