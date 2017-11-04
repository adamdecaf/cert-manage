#!/bin/bash
set -e

# Make a request to try and setup the Keychain
ssid=$(networksetup -getairportnetwork en0 | cut -c 24-)
if [ -n "$ssid" ];
then
    curl -s -o /dev/null https://google.com
fi
