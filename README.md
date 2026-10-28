# cert-manage

[![CI](https://github.com/adamdecaf/cert-manage/actions/workflows/ci.yml/badge.svg)](https://github.com/adamdecaf/cert-manage/actions/workflows/ci.yml)

**Your machine trusts hundreds of Certificate Authorities by default. Most of them you have never heard of. One bad CA is enough to break HTTPS for everyone who trusts it.**

In October 2026, the private keys of eight [eMudhra](https://emudhra.com/en/post/certificate-security-incident) intermediate CAs were compromised. Six of them could issue TLS certificates for any website. [Apple blocked](https://support.apple.com/en-us/149555) those certificates in Safari and system frameworks starting 19 October 2026, and later blocked the emSign ECC Root CA - G3. Command-line tools that still read `/etc/ssl/cert.pem` (git, curl, python3, and others) kept trusting the compromised chains until users removed the roots by hand — and a subsequent macOS update can restore Apple's copy of that file. The pattern is old: DigiNotar, Symantec, WoSign, and many others. The CA system still ships with more trust than most people need, and removing it is still harder than it should be.

`cert-manage` gives you a single CLI to **list**, **backup**, **whitelist** (distrust), and **restore** the CA trust stores on your platform and in apps such as Java, Chrome, and Firefox.

Trust should be earned, not defaulted.

## 30-second quickstart

```bash
# 1. See what you currently trust
cert-manage list
cert-manage list -count
cert-manage list -app java

# 2. Always take a backup before changing trust
cert-manage backup
cert-manage backup -app java

# 3. Whitelist: keep only the CAs you want (requires a prior backup)
cert-manage whitelist -file urls.yaml
cert-manage whitelist -app java -file urls.yaml

# 4. Roll back if something breaks
cert-manage restore
cert-manage restore -app java
```

Whitelist files are YAML or JSON. See [docs/whitelists.md](docs/whitelists.md) for fingerprints, country filters, and generating a whitelist from browser history.

> **Safety first:** Prefer experimenting against temp or container stores. Do not run `restore` against a real system CA directory until the restore fixes land (see [Safety](#safety)). Back up first, every time.

## Features

| Command | What it does |
|---------|----------------|
| [list](docs/basics.md#list) | Show trusted certificates in a platform or app store (audit) |
| [backup](docs/basics.md#backup-and-restore) / [restore](docs/basics.md#backup-and-restore) | Capture and roll back CA trust |
| [whitelist](docs/whitelists.md#whitelisting) | Distrust certificates that are not on your allowlist |
| [add](docs/basics.md#add) | Add certificates to a store |
| [connect](docs/basics.md#connect) | Probe a remote HTTPS host using a chosen store |
| [gen-whitelist](docs/whitelists.md#generating-whitelists) | Build a whitelist from browser history or URL lists |

Whitelisting also applies Chromium's certificate blacklist so known-bad CAs are never kept. That behavior cannot be disabled today.

## Platform and application support

Honest status as of late October 2026. Levels match what the code does today.

### Platforms

| Level | Platform | Notes |
|-------|----------|--------|
| **Supported** | Linux (Alpine, Debian, Ubuntu) | System CA dir list, add, whitelist, backup, restore (see Safety) |
| **Partial** | Darwin / macOS | Keychain-backed list/add/whitelist/backup/restore; system roots are SIP-protected; restore `where` support is incomplete |
| **List-only** | Windows | `list` works (PowerShell export of machine stores); add, backup, whitelist, and restore are not implemented yet |

### Applications

| Level | Application | Notes |
|-------|-------------|--------|
| **Supported** | Java (`cacerts`) | Paths differ by distro and JDK vendor; use `-app java`. Windows needs a usable `JAVA_HOME` / cacerts path. |
| **Partial** | Chrome | Linux uses NSS (`~/.pki/nssdb`); Darwin/Windows wrap the platform store. NSS backup bug [#142](https://github.com/adamdecaf/cert-manage/issues/142). |
| **Partial** | Firefox | NSS profile `cert8.db` / `cert9.db`. Same NSS backup bug [#142](https://github.com/adamdecaf/cert-manage/issues/142). |
| **Stub** | OpenSSL | Add / rehash paths exist; list, backup, remove, and restore are no-ops |

**Known issue — NSS backup ([#142](https://github.com/adamdecaf/cert-manage/issues/142)):** NSS backup currently joins the certdb directory with the wrong basename, so the real `cert9.db` / `cert8.db` may never be copied. Do not rely on NSS backups for Chrome or Firefox until that fix ships. Round-trip tests document this without changing production behavior yet.

## Safety

Certificate-store edits can break HTTPS for browsers, package managers, and language runtimes. Treat every change as privileged.

1. **Backup first.** Whitelisting without a prior backup fails on purpose. Run `cert-manage backup` (and `-app …` when targeting an app) before any whitelist.
2. **Do not restore against real system stores yet.** Linux restore currently deletes the live CA directory before copying the backup back. A failed copy can leave the machine with an empty CA dir. Until the temp-dir-then-swap fix merges, practice restore only on temp or container fixtures — never on `/etc` or `/usr` CA paths on a machine you care about.
3. **Linux restore ignores `where` / `-file`.** The CLI accepts `-file`, but `linuxStore.Restore` always uses the latest backup under `~/.cert-manage/linux/`.
4. **NSS backups are incomplete** until [#142](https://github.com/adamdecaf/cert-manage/issues/142) is fixed (see above).
5. **`-dry-run` is not implemented yet** (see Roadmap). Until then, use `list` and `connect` to inspect impact, and keep a known-good backup.

## Install

Download a binary from the [latest release](https://github.com/adamdecaf/cert-manage/releases) (tagged `0.1.0`; module version is `0.1.1-dev`), or build from source (Go **1.27** required):

```bash
git clone https://github.com/adamdecaf/cert-manage.git
cd cert-manage
make build          # produces ./cert-manage
# or cross-compile:
make dist           # linux / osx / windows binaries under bin/
```

You can also install with the Go toolchain:

```bash
go install github.com/adamdecaf/cert-manage@latest
```

### Usage examples

```bash
# Platform store
cert-manage list
cert-manage list -format table       # short (default), table, openssl, observatory
cert-manage list -format openssl
cert-manage list -ui web             # cli (default) or web

# Apps
cert-manage list -app java
cert-manage list -app chrome
cert-manage list -app firefox

# From a file or Mozilla certdata URL
cert-manage list -file example.crt
cert-manage list -url https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt

# Add
cert-manage add -file cert.pem
cert-manage add -file cert.pem -app java

# Whitelist, backup, restore
cert-manage backup
cert-manage whitelist -file urls.yaml
cert-manage restore                 # latest backup
cert-manage restore -file <path>    # note: Linux currently ignores -file

# Generate a whitelist
cert-manage gen-whitelist -out whitelist.json -from firefox
cert-manage gen-whitelist -out whitelist.json -from browsers
cert-manage gen-whitelist -out whitelist.json -file urls.txt

# Verify connectivity after a change
cert-manage connect https://example.com
cert-manage connect -app java https://example.com

cert-manage version
```

More detail: [docs/basics.md](docs/basics.md), [docs/whitelists.md](docs/whitelists.md).

## Building and testing

Go **1.27** is required (`go.mod`).

```bash
make build          # vet + unit tests + binary
make test           # full suite (uses Docker when available)
MOCKED=true make test   # skip Docker-backed tests
```

Backup/restore tests use **temp directories only** and refuse paths under `/etc` or `/usr`. Do not point destructive tests at a real system CA directory.

Cross-platform binaries: `make linux`, `make osx`, `make win`, or `make dist`. CI cross-compiles `linux`/`darwin`/`windows` (`amd64`/`arm64`), runs unit tests on Ubuntu/macOS/Windows runners, and runs Alpine/Debian/Ubuntu Docker distro suites.

## Contributing

Help with docs, bugfixes, tests, and new or deeper store support is welcome. One focused PR at a time works best.

1. Fork and clone the repo.
2. Use Go 1.27; run `make build` and `make test` (or `MOCKED=true make test`) before opening a PR.
3. Prefer temp / container stores in tests — never point destructive tests at a real system CA directory.

This project follows the [Google Code of Conduct](https://opensource.google.com/conduct/).

## Roadmap

Daily plan (2026). Dates are goals, not promises. App tests (Java, browsers) should run across multiple platforms — store paths differ.

| When | Focus | Tracking |
|------|--------|----------|
| **Oct 29** | Java backup/restore on the Linux distro matrix | [#230](https://github.com/adamdecaf/cert-manage/issues/230) |
| **Oct 30** | Safe Linux restore (copy to a temp dir, then swap) | [#231](https://github.com/adamdecaf/cert-manage/issues/231) |
| **Oct 31** | Restore honors `where` / `-file`; NSS backup path fix | [#231](https://github.com/adamdecaf/cert-manage/issues/231) |
| **Nov 1** | `-dry-run` for destructive commands | [#232](https://github.com/adamdecaf/cert-manage/issues/232) |
| **Nov 2** | Java on Mac | [#230](https://github.com/adamdecaf/cert-manage/issues/230) |
| **Nov 3** | More Linux distros (Rocky, Fedora, Arch) | [#233](https://github.com/adamdecaf/cert-manage/issues/233) |
| **Nov 4** | Firefox test suite | [#236](https://github.com/adamdecaf/cert-manage/issues/236) |
| **Nov 5** | Chrome test suite | [#236](https://github.com/adamdecaf/cert-manage/issues/236) |
| **Nov 6** | Raise store / cmd coverage | [#234](https://github.com/adamdecaf/cert-manage/issues/234) |
| **Nov 7** | Windows beyond list-only | [#235](https://github.com/adamdecaf/cert-manage/issues/235) |
| **Nov 8** | **0.2.0** release | [#237](https://github.com/adamdecaf/cert-manage/issues/237) |
| **Nov 9** | Adoption push | [#237](https://github.com/adamdecaf/cert-manage/issues/237) |

## Why this matters (research)

- [Analysis of the HTTPS Certificate Ecosystem](docs/papers/https-imc13.pdf) (2013) — more than **1,800 entities** able to issue certificates for any website; compromise of one intermediate would force ~26% of HTTPS sites to re-issue.
- [CAge — Taming Certificate Authorities by Inferring Restricted Scopes](docs/papers/cage-fc13.pdf) — simple inference rules cut attack surface nearly tenfold without blocking most CA activity.
- [You Won't Be Needing These Any More: On Removing Unused Certificates From Trust Stores](docs/papers/on-removing-unused-certs.pdf) — only about two-thirds of trusted roots were observed signing HTTPS certificates.

## Background: CA incidents

Incidents keep showing that "trusted by default" is not the same as "trustworthy." Beyond [eMudhra / Apple (October 2026)](https://support.apple.com/en-us/149555), a non-exhaustive historical sample:

- [DigiNotar](https://en.wikipedia.org/wiki/DigiNotar)
- [CNNIC](https://blog.mozilla.org/security/2015/03/23/revoking-trust-in-one-cnnic-intermediate-certificate/)
- [Symantec issues](https://wiki.mozilla.org/CA:Symantec_Issues)
- [WoSign / WoTrus](https://wiki.mozilla.org/CA:WoSign_Issues)
- [Trustico CEO emailing DigiCert ~23k private keys](https://groups.google.com/forum/#!topic/mozilla.dev.security.policy/wxX4Yv0E3Mk)
- StartCom ([StartEncrypt](https://www.computest.nl/blog/startencrypt-considered-harmful-today/)), GlobalSign cross-signing mistakes, vendor-installed roots (e.g. [DYMO](https://github.com/njh/dymo-root-ca-security-risk), [Savitech](https://www.kb.cert.org/vuls/id/446847))
- See Mozilla's [CA Incident Dashboard](https://wiki.mozilla.org/CA/Incident_Dashboard) and [dev-security-policy](https://groups.google.com/forum/#!forum/mozilla.dev.security.policy)

Vendors and browsers react after the fact. `cert-manage` is for putting that control on your own machine before the next incident.

## Related projects

- [certpatrol](http://patrol.psyced.org/)
- [chengr28/RevokeChinaCerts](https://github.com/chengr28/RevokeChinaCerts)
- [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide#certificate-authorities)
- [kirei/catt](https://github.com/kirei/catt)
- [mkcert.org](https://mkcert.org/)
- [mozilla/tls-observatory](https://github.com/mozilla/tls-observatory)
- [MSylvia/CertTrustSetter](https://github.com/MSylvia/CertTrustSetter)
- [nabla-c0d3/trust_stores_observatory](https://github.com/nabla-c0d3/trust_stores_observatory)
- [ntkme/security-trust-settings-tools](https://github.com/ntkme/security-trust-settings-tools)
- [sebdeckers/tls-keygen](https://gitlab.com/sebdeckers/tls-keygen)
- [storborg/dotfiles paranoia.py](https://github.com/storborg/dotfiles/blob/master/scripts/paranoia.py)
- [SSL Blacklist 4.0](http://www.codefromthe70s.org/sslblacklist.aspx)

## Related reading

- [SSL and the Future of Authenticity](https://moxie.org/blog/ssl-and-the-future-of-authenticity/)
- [Mozilla Certificate Policy](https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/)
- [Mozilla CA Incident Dashboard](https://wiki.mozilla.org/CA/Incident_Dashboard)
- [mozilla.dev.security.policy](https://groups.google.com/forum/#!forum/mozilla.dev.security.policy)
- [TLS Working Group](https://datatracker.ietf.org/wg/tls/charter/)
- Apple: [About the compromised eMudhra intermediate CAs](https://support.apple.com/en-us/149555)
- eMudhra: [Statement on certificate security incident](https://emudhra.com/en/post/certificate-security-incident)

## License

Apache License 2.0. See [LICENSE](LICENSE).
