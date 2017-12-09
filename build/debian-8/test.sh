#!/bin/bash

total=174
after=5

# Verify we're starting with the correct number of certs
/bin/cert-manage list -count | grep $total

# Make a backup
/bin/cert-manage backup

# Quick check
ls -1 /usr/share/ca-certificates/* | wc -l | grep 177
ls -1 /usr/share/ca-certificates.backup/* | wc -l | grep 177

# Whitelist and verify
/bin/cert-manage whitelist -file /whitelist.json
/bin/cert-manage list -count | grep $after

# Restore
/bin/cert-manage restore
/bin/cert-manage list -count | grep $total

echo "Debian 8 Passed"
