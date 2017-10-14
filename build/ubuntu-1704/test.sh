#!/bin/bash
set -e

cd build/ubuntu-1704/
cp ../../bin/cert-manage-linux-amd64 cert-manage
cp ../../testdata/globalsign-whitelist.json whitelist.json

total=149
after=6
cat > main <<EOF
#!/bin/sh
set -e

# Verify we're starting with the correct number of certs
/bin/cert-manage -list | wc -l | grep $total

# Make a backup
/bin/cert-manage -backup

# Quick check
ls -l /usr/share/ca-certificates/* | wc -l | grep $total
ls -l /usr/share/ca-certificates.backup/* | wc -l | grep $total

# Whitelist and verify
/bin/cert-manage -whitelist /whitelist.json
/bin/cert-manage -list | wc -l | grep $after

# Restore
EOF

chmod +x main
docker build -t cert-manage-ubuntu-1704:latest . 2>&1 > test.log
docker run -i --entrypoint /bin/main cert-manage-ubuntu-1704:latest 2>&1 >> test.log
