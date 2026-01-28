#!/bin/bash

docker run -it -p 8080:8080 -p 8000:8000 -v ./moppy:/moapy/moppy -v .:/moapy/scripts rbaxim/mop --cmd "uv run /moapy/scripts/mathEVAL.py" --host "0.0.0.0"