#!/bin/bash
set -e

# Run each build's tests
platforms=(alpine-36 debian-8 debian-9 ubuntu-1604 ubuntu-1704)
for plat in "${platforms[@]}"
do
    echo "CI: $plat"
    ./build/"$plat"/test.sh
done
