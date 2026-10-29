---
layout: default
title: Backup and restore
---

# Backup and restore

Certificate-store edits can break HTTPS for browsers, package managers, and language runtimes. Treat every change as privileged.

## Best practices

1. **Backup first.** Allowlisting without a prior backup fails on purpose. Run `cert-manage backup` (and `-app …` when targeting an app) before any allowlist.
2. **Prefer temp or container stores** when experimenting. Do not point destructive tests at real `/etc` or `/usr` CA paths.
3. **Verify after changes** with `cert-manage list` and `cert-manage connect https://…`.
4. **Keep a known-good backup** until you confirm the machine still reaches the sites and tools you need.

Add `-dry-run` to `backup` or `restore` to see exactly which files would be written or copied, without touching the store.

## Where backups are stored

Parent directory (created as needed):

| OS | Path |
|----|------|
| Linux, Windows | `~/.cert-manage/` |
| Darwin | `~/Library/cert-manage/` |

| Store | Layout under the parent |
|-------|-------------------------|
| Linux platform | `linux/<unix-timestamp>/` — mirror of the live CA **directory** (`/usr/share/ca-certificates` or Fedora anchors dir) |
| Darwin platform | `darwin/<unix-timestamp>/login.keychain/<sha256>.crt` — PEM exports of login-keychain certs |
| Java | `java/cacerts-<unix-timestamp>.bck` (filename taken from the keystore basename) |
| Chrome / Firefox (NSS) | `chrome/<unix-timestamp>/` or `firefox/<unix-timestamp>/` — full profile file set (see below) |

`GetLatestBackup` picks the lexicographically largest entry in that store’s folder (timestamped names sort correctly).

## Linux: temp-dir swap and rollback

`linuxStore.Restore` does **not** delete the live CA directory before copying. It:

1. Mirrors the backup into a sibling temp directory (`<ca.dir>.restore-tmp`).
2. Renames the live directory aside to `<ca.dir>.restore-old`. It always uses that fixed path, so an operator can find it even after a crash; restore prints the path only when a failure leaves `<ca.dir>.restore-old` in place.
3. Renames the temp directory into place as the live CA dir.
4. Runs `update-ca-certificates` / `update-ca-trust` (via `sudo` unless already root).
5. On refresh failure, moves the failed tree to `<ca.dir>.restore-failed` and renames the aside directory back.
6. On success, removes the aside directory.

If the swap rename itself fails after the live tree was moved aside, the previous directory is renamed back. A failed mirror leaves the live directory untouched.

`Restore` honors an explicit path (`cert-manage restore -file …` / the store `where` argument). Empty `where` uses the latest backup under `~/.cert-manage/linux/`.

## NSS: full file set

NSS backups for Chrome (Linux) and Firefox copy whichever members of the profile set exist:

| Style | Files |
|-------|-------|
| `cert9.db` present | `cert9.db`, `key4.db`, `pkcs11.txt` |
| else `cert8.db` | `cert8.db`, `key3.db`, `secmod.db` |

### Temp-dir swap and rollback

`nssStore.Restore` does **not** copy profile files straight onto the live paths. It:

1. Stages the backup set into a sibling temp directory (`<profile>.restore-tmp`).
2. Moves each existing live file aside under `<profile>.restore-old/`. It always uses that fixed path, so an operator can find it even after a crash; restore prints the path only when a failure leaves `<profile>.restore-old/` in place.
3. Renames each staged file into the live profile.
4. On any staging or swap failure, rolls live files back from the aside directory and removes the temp dirs.
5. On success, removes the temp and aside directories.

A failed stage leaves the live profile files untouched. Restore from a **legacy single file** uses the same stage-then-swap path onto `cert9.db` (or `cert8.db` if the backup basename contains `cert8`). Explicit `-file` / `where` is honored.

## Java

Backup copies the live `cacerts` file into `~/.cert-manage/java/` (or `~/Library/cert-manage/java/` on Darwin). Restore copies the chosen backup over the live keystore (`SudoCopyFile` when permissions require it). Explicit `-file` is honored.

## Darwin notes

- System root keychain is SIP-protected and is not rewritten.
- Backup exports certificates from the **login** keychain only.
- Restore clears “Never Trust” overrides for Apple system roots where applicable, then re-adds missing login-keychain certs from the **latest** backup. The `where` / `-file` argument is currently unused (always `GetLatestBackup()`).

## Windows

Platform Add, Backup, Remove, and Restore are unimplemented (return success with no work). Only `list` reads the machine certificate stores.

[← Home](index.md)
