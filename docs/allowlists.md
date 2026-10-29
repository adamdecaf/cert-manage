---
layout: default
title: Allowlists
---

# Allowlists

## Allowlisting

### Configuration

Allowlists represent an operation which disables certificate trust in a certificate store. The filters presented for an allowlist are:

- `Fingerprints`: The SHA256 fingerprint of a certificate. This value will be unique across certificates given their contents are unique.
- `Countries`: ISO 3166-1 two-letter country codes of certificates to keep. (e.g. `US` - United States and `JP` - Japan)

Allowlists are stored in yaml or json files. There is a basic structure to them which allows for multiple methods of allowlisting. The structure looks like:

```json
# Optional array of SHA256 certificate fingerprints
fingerprints:
 - "050cf9fa95e40e9bddedaeda6961f6168c1279c4660172479cdd51ab03cea62c"

# Optional array of ISO 3166-1 Country Codes
countries:
 - "US"
 - "JP"
```

```json
{
  "Fingerprints": [
    "050cf9fa95e40e9bddedaeda6961f6168c1279c4660172479cdd51ab03cea62c"
  ],
  "Countries": [
    "GB"
  ]
}
```

To apply an allowlist against a platform:

```
$ cert-manage allowlist -file wh.json
Allowlist completed successfully
```

You can also apply an allowlist against an application's certificate store:

```
$ cert-manage allowlist -file wh.json -app java
Allowlist completed successfully
```

The older `whitelist` command name remains as a hidden alias.


## Generating allowlists

`cert-manage` supports generating allowlists from browser history. Either all browsers `-from browser` or specific browsers `-from chrome`.

```
$ cert-manage gen-allowlist -from browser -out wh.yaml
CA                                             Fingerprint      Count Example DNSNames
GeoTrust Inc.                                  ff856a2d251dcd88 13    plus.google.com, accounts.google.com, hangouts.google.com
...

$ cert-manage gen-allowlist -from chrome -out wh.yaml
CA                                             Fingerprint      Count Example DNSNames
GeoTrust Inc.                                  ff856a2d251dcd88 13    plus.google.com, accounts.google.com, hangouts.google.com
...
```

The older `gen-whitelist` command name remains as a hidden alias.

### Blocklisted certificates

`cert-manage` includes the [Chromium certificate blocklist](https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/blocklist/) to never allowlist certificates which are generally regarded by the industry as untrusted.

There is currently no way to disable this behavior.

### Files

`cert-manage` can also generate allowlists from a given file. This could be a text file with a url on each line, or a comma separated file with urls in one column per row.

##### Plain text files

```
$ cat urls.txt
https://google.com
https://yahoo.com
https://bing.com

$ cert-manage gen-allowlist -out wh.yaml -file urls.txt
CA                             Fingerprint      Count Example DNSNames
DigiCert Inc, www.digicert.com 7431e5f4c3c1ce46 1     yahoo.com
Baltimore, CyberTrust          16af57a9f676b0ab 1     bing.com
GeoTrust Inc.                  ff856a2d251dcd88 1     google.com

$ cat wh.yaml
fingerprints:
    - 7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf
    - 16af57a9f676b0ab126095aa5ebadef22ab31119d644ac95cd4b93dbf3f26aeb
    - ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a
```


##### CSV files

There are several services which offer "Top N Domains" lists. One widely used option is the [Tranco list](https://tranco-list.eu/), which offers the list as a CSV file. `cert-manage` can generate an allowlist from such a file. The file may also be compressed with gzip.

```
$ cert-manage gen-allowlist -out wh.yaml -file tranco-top-1m.csv.gz
CA                             Fingerprint      Count Example DNSNames
DigiCert Inc, www.digicert.com 7431e5f4c3c1ce46 1     yahoo.com
Baltimore, CyberTrust          16af57a9f676b0ab 1     bing.com
GeoTrust Inc.                  ff856a2d251dcd88 1     google.com
...
```
