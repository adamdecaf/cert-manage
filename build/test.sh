#!/bin/bash

# Run each build's tests
platforms=(alpine-36 debian-8 debian-9 ubuntu-1604 ubuntu-1704)
for plat in "${platforms[@]}"
do
    echo "CI: $plat"
    ./build/"$plat"/test.sh
    if [ ! $? -eq 0 ];
    then
        cat ./build/"$plat"/test.log
        exit 1
    fi
done
