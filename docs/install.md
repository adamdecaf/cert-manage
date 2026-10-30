---
layout: default
title: Install
---

# Install

Module version on `master` is `0.1.1-dev`. Tagged releases start at `0.1.0`. Building requires **Go 1.27**.

## Release binaries

Download a pre-built binary from the [latest release](https://github.com/adamdecaf/trustprune/releases).

Cross-compile locally with Make (outputs under `bin/`):

```bash
make linux    # bin/trustprune-linux-$(GOARCH)
make osx      # bin/trustprune-osx-$(GOARCH)
make win      # bin/trustprune-$(GOARCH).exe
make dist     # all three
```

## go install

```bash
go install github.com/adamdecaf/trustprune@latest
```

That installs a binary named `trustprune` (Go uses the last path element). `make build` also creates a local `cert-manage` symlink alias.

## Build from source

```bash
git clone https://github.com/adamdecaf/trustprune.git
cd trustprune
make build          # vet + unit tests + ./trustprune (+ cert-manage symlink)
```

Useful test targets:

```bash
make check                 # vet + unit tests under ./pkg and .
make test                  # check + Docker-backed integration when available
MOCKED=true make test      # skip Docker-backed tests
```

[← Home](index.md)
