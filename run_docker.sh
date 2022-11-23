#!/usr/bin/env bash
set -o errexit  # fail on first error
set -o nounset  # fail on undef var
set -o pipefail # fail on first error in pipe

curl --silent --fail --show-error --location --remote-name --remote-header-name\
  https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor/releases/latest/download/token_extractor_docker.zip
unzip token_extractor_docker.zip
cd token_extractor_docker
docker_image=$(docker build -q .)
docker run --rm -it $docker_image
docker rmi $docker_image
cd ..
rm -rf token_extractor_docker token_extractor_docker.zip
