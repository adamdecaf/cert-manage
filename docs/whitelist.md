## Whitelists

-- todo

## Configuration

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
