#!/bin/bash
set -e

echo "Clamav"

# Verify we find certs
# /bin/cert-manage -list -app clamav -count | grep ...

# Make a backup
# /bin/cert-manage -backup

# Quick check
# ...

# Whitelist and verify
# /bin/cert-manage -whitelist -file /whitelist.json
# /bin/cert-manage -list -count | grep ...

# Restore
# /bin/cert-manage -restore
# /bin/cert-manage -list -count | grep ...
