#!/bin/bash
set -e

platform='linux'
if [[ `uname -s` == 'Darwin' ]];
then
    platform='osx'
fi

# Google whitelists
./bin/gen-whitelist-$platform -file whitelists/google.json -google
./bin/gen-whitelist-$platform -file whitelists/google-suggested.json -google-suggested

# Digicert
./bin/gen-whitelist-$platform -file whitelists/digicert.json -digicert

# Visa
./bin/gen-whitelist-$platform -file whitelists/visa.json -visa
