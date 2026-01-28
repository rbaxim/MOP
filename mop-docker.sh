#!/bin/bash

MOPPY_DIR=$(realpath ./moppy)
SCRIPTS_DIR=$(realpath ./scripts)

if [ "$1" == "build" ]; then
    docker build . -t rbaxim/mop:latest
    exit 0
elif [ "$1" == "run" ]; then
    docker run -it -p 8080:8080 -p 8000:8000 -v "$MOPPY_DIR":/moapy/moppy -v "$SCRIPTS_DIR":/moapy/scripts rbaxim/mop "${@:2}"
else
    echo "Usage: ./docker_run.sh [build|run]"
fi