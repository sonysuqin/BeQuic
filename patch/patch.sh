#!/bin/bash

echo Patching chromium.
cp ./BUILD.gn ../../chromium/src/net/
cp ../src/chromium/* ../../chromium/src/net/tools/quic

echo Patch done.
