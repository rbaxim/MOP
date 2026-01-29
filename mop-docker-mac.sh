#!/bin/zsh

moppy_dir=$(mkdir -p ./moppy && cd ./moppy && pwd)
scripts_dir=$(mkdir -p ./scripts && cd ./scripts && pwd)

if [ "$1" == "build" ]; then
    docker build . -t rbaxim/mop:latest
    exit 0
elif [ "$1" == "run" ]; then
    docker run -it --init -p 8080:8080 -p 8000:8000 -v "$moppy_dir:/moapy/moppy" -v "$scripts_dir:/moapy/scripts" rbaxim/mop "${@:2}"
else
    echo "Usage: ./mop-docker-mac.sh [build|run]"
fi