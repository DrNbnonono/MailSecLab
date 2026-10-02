#!/bin/bash
# Run this yourself in WSL Ubuntu-22, from anywhere.
# These three images are not on this machine. Everything else used by the
# later weeks is already local, or is built from debian:bookworm-slim.
set -eu
docker pull roundcube/roundcubemail:1.6.19-apache
docker pull djmaze/snappymail:v2.38.2
docker pull debian:buster-slim
echo "---- frozen ids ----"
docker image inspect --format '{{index .RepoTags 0}} {{.Id}}' \
  roundcube/roundcubemail:1.6.19-apache \
  djmaze/snappymail:v2.38.2 \
  debian:buster-slim
