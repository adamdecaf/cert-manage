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

echo "Platform tests"
# Verify we're starting with the correct number of certs
/bin/cert-manage -list | wc -l | grep $total

# Make a backup
/bin/cert-manage -backup

# Quick check
ls -l /usr/share/ca-certificates/* | wc -l | grep $total
ls -l /usr/share/ca-certificates.backup/* | wc -l | grep $total

# Whitelist and verify
/bin/cert-manage -whitelist -file /whitelist.json
/bin/cert-manage -list | wc -l | grep $after

# Restore
/bin/cert-manage -restore
/bin/cert-manage -list | wc -l | grep $total

## Chrome
echo "Chrome tests"
timeout 15s chromium-browser --no-sandbox --headless https://google.com 2>&1 >> /var/log/chrome.log
# /bin/cert-manage -list -app chrome | wc -l

## Firefox
echo "Firefox tests"
set +e
timeout 15s firefox --headless https://google.com 2>&1 >> /var/log/firefox.log
code=\$?
if [ "\$code" -ne "124" ];
then
  exit \$code
fi
echo "firefox was forced to quit, code=\$code"
set -e
/bin/cert-manage -list -app firefox | wc -l | grep -E [56]

# Take a backup
[ ! -d ~/.cert-manage/firefox ]
/bin/cert-manage -backup -app firefox
ls -1 ~/.cert-manage/firefox | wc -l | grep 1

# Whitelist
/bin/cert-manage -whitelist -file /whitelist.json -app firefox
/bin/cert-manage -list -app firefox | wc -l | grep 2

# Restore that backup
for db in \$(ls -1 ~/.mozilla/firefox/*.default/cert8.db | head -n1)
do
    # Force a difference we'd notice after a restore happens
    echo a > "\$db"
    /bin/cert-manage -restore -app firefox

    # Check we actaully restored a file
    size=\$(stat --printf="%s" ~/.mozilla/firefox/*.default/cert8.db)
    if [ ! "\$size" -gt "2" ];
    then
        echo "failed to restore firefox cert8.db properly"
        exit 1
    fi

    ls -l "\$db"
done

# Verify restore
/bin/cert-manage -list -app firefox | wc -l | grep -E [56]

# Java
echo "Java"
/bin/cert-manage -list -app java | wc -l | grep 149
/bin/cert-manage -backup -app java
ls -1 ~/.cert-manage/java | wc -l | grep 1
# Break the keystore
echo a > /usr/lib/jvm/java-9-openjdk-amd64/lib/security/cacerts
# Restore
/bin/cert-manage -restore -app java
# Verify restore
size=\$(stat --printf="%s" /usr/lib/jvm/java-9-openjdk-amd64/lib/security/cacerts)
if [ ! "\$size" -gt "2" ];
then
    echo "failed to restore java cacerts properly"
    exit 1
fi

echo "Finished"
EOF

chmod +x main
docker build -t cert-manage-ubuntu-1704:latest . 2>&1 > test.log
docker run -i --entrypoint /bin/main cert-manage-ubuntu-1704:latest 2>&1 >> test.log
