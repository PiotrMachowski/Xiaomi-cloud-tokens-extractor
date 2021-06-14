#!/usr/bin/env bash

wget -q https://github.com/PiotrMachowski/Xiaomi-cloud-tokens-extractor/releases/latest/download/token_extractor.zip
unzip token_extractor.zip
cd token_extractor
pip3 install -r requirements.txt
python3 token_extractor.py
cd ..
rm -rf token_extractor token_extractor.zip
