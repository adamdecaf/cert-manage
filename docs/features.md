# Features

### List

The cli sub-command `list` will output a list of certificates installed (and trusted) in the certificate store. This option defaults to the platform (Linux, OSX, or Windows), but can be switched to an application via the `-app` flag.

Show certificates installed in the platform:

```
$ cert-manage list
Subject                                                      Issuer                                                       Public Key Algorithm SHA256 Fingerprint Not Before Not After
A-Trust-nQual-01                                             A-Trust-nQual-01                                             RSA                  7b1f8d8eff5d7349   2004-11-30 2014-11-30
A-Trust-nQual-03                                             A-Trust-nQual-03                                             RSA                  793cbf4559b9fde3   2005-08-17 2015-08-17
...
```

Show certificates installed for an application

```
$ cert-manage list -app firefox
Subject                                             Issuer                                                       Public Key Algorithm SHA256 Fingerprint Not Before Not After
AlphaSSL CA - SHA256 - G2                           GlobalSign Root CA                                           RSA                  ee793643199474ed   2014-02-20 2024-02-20
Amazon                                              Amazon Root CA 1                                             RSA                  f55f9ffcb83c7345   2015-10-22 2025-10-19
Amazon Root CA 1                                    Starfield Services Root Certificate Authority - G2           RSA                  87dcd4dc74640a32   2015-05-25 2037-12-31
```

Note: You can specify `-format raw` to output all details of each certificate, but the result won't be in a table layout.

```
$ cert-manage list -format raw
Certificate
  SHA1 Fingerprint - 801d62d07b449d5c5c035c98ea61fa443c2a58fe
  SHA256 Fingerprint - d1c339ea2784eb870f934fc5634e4aa9ad5505016401f26465d37a574663359f
  Signature - 5947ac21848a17c99c89531eba80851ac63c4e3eb19cb67cc6925d186402e3d3060811617c63e32b9d31037076d2a328a0f4bb9a6373ed6de52adbed14a92bc63611d02beb078ba5da9e5c199d5612f55429c805edb2122a8df4031bffe7921087b03ab5c39d053712a3c7f415b9d5a439169b533a2391f1a882a26a8868c1790222bcaaa6d6aedfb0145fb887d0dd7c7f7bffaf1ccfe6db07ad5edb859dd02b0d33db04d1e64940132b76fb3ee99c890f15ce18b08578214f6b4f0efa3667cd07f2ff08d0e2ded9bf2aafb88786213c04cab794687fcf3ce998d738ffecc0d950f02e4b58ae466fd02ec360da725572bd4c459e61babf84819203d1d2697cc5
  Signature Algorithm: SHA1-RSA
  SerialNumber: 946059622
  Public Key Algorithm - RSA
  Issuer CommonName - Entrust.net Certification Authority (2048), SerialNumber -
  Subject CommonName - Entrust.net Certification Authority (2048), SerialNumber -
  NotBefore - 1999-12-24 17:50:51 +0000 UTC, NotAfter - 2019-12-24 18:20:51 +0000 UTC
  IsCA - false
  MaxPathLen - 0
  DNSNames
  EmailAddresses
  IPAddresses
  PermittedDNSDomains
  CRLDistributionPoints
```

### Whitelisting

##### Configuration

Whitelists represent an operation which disables certificate trust in a certificate store. The filters presented for a whitelist are:

- `Fingerprint`: The SHA256 fingerprint of a certificate. This value will be unique across certificates given their contents are unique.

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

To apply a whitelist against a platform:

```
$ cert-manage whitelist -file wh.json
Whitelist completed successfully
```

You can also apply a whitelist against an application's certificate store:

```
$ cert-manage whitelist -file wh.json -app java
Whitelist completed successfully
```

### Backup and Restore

It's important to be able to rollback changes to your certificate store. These changes can be dangerous if done incorrectly as many websites you visit might partially quit loading.

To capture a backup:

```
$ cert-manage backup
Backup completed successfully
```

To capture a backup for an application

```
$ cert-manage backup -app java
Backup completed successfully
```
