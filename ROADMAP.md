## cert-manage Roadmap

### 0.1.0

#### Get linux support 100%

- `escalate via sudo/su if needed and able`: https://github.com/adamdecaf/cert-manage/issues/134
- Are we using the right cadir values?: https://github.com/adamdecaf/cert-manage/issues/135
  - Drop `backup` field, switch to timestamp'd backups like the other stores

#### Whitelist generation

- "better grouping of CA certs/chains": https://github.com/adamdecaf/cert-manage/issues/124
  - Take the most-parent root. Ignore intermediates

### whitelist format as yaml

- https://github.com/adamdecaf/cert-manage/issues/109


### 0.2.0

store/java: accept -file
 - https://github.com/adamdecaf/cert-manage/issues/126

cmd: allow -app to be a list
 - https://github.com/adamdecaf/cert-manage/issues/119

cmd: "known urls"
 - https://github.com/adamdecaf/cert-manage/issues/136

cmd/gen-whitelist:
 - "whitelist generation is slow": https://github.com/adamdecaf/cert-manage/issues/123

nss: cert9.db support
 - https://github.com/adamdecaf/cert-manage/issues/142
 - https://wiki.mozilla.org/NSS_Shared_DB

firefox tests:
 - https://github.com/adamdecaf/cert-manage/issues/89
 - https://github.com/adamdecaf/cert-manage/issues/105

chrome tests
 - https://github.com/adamdecaf/cert-manage/issues/83

check for backup on -whitelist
 - https://github.com/adamdecaf/cert-manage/issues/53

### Future

output formats:
 - https://github.com/adamdecaf/cert-manage/issues/139

openssl: https://github.com/adamdecaf/cert-manage/issues/31
libressl: https://github.com/adamdecaf/cert-manage/issues/143
OSX: https://github.com/adamdecaf/cert-manage/issues/9
Windows: https://github.com/adamdecaf/cert-manage/issues/8

ui/web: better design
 - https://github.com/adamdecaf/cert-manage/issues/140
 - https://github.com/adamdecaf/cert-manage/issues/103

ui/web: checklist for removal
 - https://github.com/adamdecaf/cert-manage/issues/98
