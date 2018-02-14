## Whitelisting

### Configuration

Whitelists represent an operation which disables certificate trust in a certificate store. The filters presented for a whitelist are:

- `Fingerprint`: The SHA256 fingerprint of a certificate. This value will be unique across certificates given their contents are unique.

Whitelists are stored in json files. There is a basic structure to them which allows for multiple methods of whitelisting. The structure looks like:

```json
{
  "Fingerprints": [
    "050cf9fa95e40e9bddedaeda6961f6168c1279c4660172479cdd51ab03cea62c"
  ]
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


## Generating Whitelists
