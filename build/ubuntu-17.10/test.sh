#!/bin/bash
set -e

echo "Platform tests"
# Verify we're starting with the correct number of certs
/bin/cert-manage -list -count | grep 148

# Make a backup
/bin/cert-manage -backup

# Quick check
ls -1 /usr/share/ca-certificates/* | wc -l | grep 148
ls -1 /usr/share/ca-certificates.backup/* | wc -l | grep 148

# Whitelist and verify
/bin/cert-manage -whitelist -file /whitelist.json
/bin/cert-manage -list -count | grep 5

# Restore
/bin/cert-manage -restore
/bin/cert-manage -list -count | grep 148

## Chrome
echo "Chrome tests"
timeout 15s chromium-browser --no-sandbox --headless https://google.com 2>&1 >> /var/log/chrome.log
# /bin/cert-manage -list -app chrome -count

## Firefox
echo "Firefox tests"
set +e
timeout 15s firefox --headless https://google.com 2>&1 >> /var/log/firefox.log
code=$?
if [ "$code" -ne "124" ];
then
  exit $code
fi
echo "firefox was forced to quit, code=$code"
set -e
count=$(/bin/cert-manage -list -app firefox -count)
echo "Cert count from firefox: $count"
echo "$count" | grep -E 4

# Take a backup
[ ! -d ~/.cert-manage/firefox ]
/bin/cert-manage -backup -app firefox
ls -1 ~/.cert-manage/firefox | wc -l | grep 1

# Whitelist
/bin/cert-manage -whitelist -file /whitelist.json -app firefox
/bin/cert-manage -list -app firefox -count | grep 1

# Restore that backup
for db in $(ls -1 ~/.mozilla/firefox/*.default/cert8.db | head -n1)
do
    # Force a difference we'd notice 5 a restore happens
    echo a > "$db"
    /bin/cert-manage -restore -app firefox

    # Check we actaully restored a file
    size=$(stat --printf="%s" ~/.mozilla/firefox/*.default/cert8.db)
    if [ ! "$size" -gt "2" ];
    then
        echo "failed to restore firefox cert8.db properly"
        exit 1
    fi

    ls -l "$db"
done

# Verify restore
/bin/cert-manage -list -app firefox -count | grep -E 4

# Java
echo "Java"
/bin/cert-manage -list -app java -count | grep 148
/bin/cert-manage -backup -app java
ls -1 ~/.cert-manage/java | wc -l | grep 1
# Break the keystore
echo a > /usr/lib/jvm/java-9-openjdk-amd64/lib/security/cacerts
# Restore
/bin/cert-manage -restore -app java
# Verify restore
size=$(stat --printf="%s" /usr/lib/jvm/java-9-openjdk-amd64/lib/security/cacerts)
if [ ! "$size" -gt "2" ];
then
    echo "failed to restore java cacerts properly"
    exit 1
fi
/bin/cert-manage -whitelist -file /whitelist.json -app java
/bin/cert-manage -list -app java -count | grep 9

echo "Ubuntu 17.10 Passed"
