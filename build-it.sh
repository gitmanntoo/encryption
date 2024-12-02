#!/bin/bash

# build and run Dockerfile with a local data directory.
TAG=dockmann/encryption:latest

# build and run the container
# - multi-platform build requires containerd (https://docs.docker.com/build/building/multi-platform/)
docker buildx build --platform linux/amd64,linux/arm64 --tag ${TAG} . 
