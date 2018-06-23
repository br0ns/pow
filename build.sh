#!/bin/sh
set -e
set -x
cd "$(dirname "$0")"
docker build -t pow .
docker run --user=$(id -u):$(id -g) --rm -v "$(pwd):/pow" -w /pow pow
