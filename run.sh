#!/usr/bin/env bash
set -o errexit  # fail on first error
set -o nounset  # fail on undef var
set -o pipefail # fail on first error in pipe

curl --silent --fail --show-error --location --remote-name --remote-header-name\
  https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor/releases/latest/download/token_extractor.zip
unzip token_extractor.zip
cd token_extractor
pip3 install -r requirements.txt
python3 token_extractor.py
cd ..
rm -rf token_extractor token_extractor.zip
