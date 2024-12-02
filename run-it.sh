#!/bin/bash

# build and run Dockerfile with a local data directory.
TAG=dockmann/encryption:latest

# set data directory from the command line or a default.
DATA_DIR=$(pwd)/data
if [ -n "$1" ]; then
    DATA_DIR=$1
fi

# build and run the container
docker run -it --rm ${TAG} $@
