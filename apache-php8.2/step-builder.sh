#!/bin/sh
set -euo pipefail

case $(uname -m) in
    x86_64)
        make binary-linux-amd64
        cp /go/step-cli/output/binary/linux-amd64/bin/step /usr/local/bin/
        ;;
    armv7*)
        make binary-linux-armv7
        cp /go/step-cli/output/binary/linux-armv7/bin/step /usr/local/bin/
        ;;
    aarch64)
        make binary-linux-arm64
        cp /go/step-cli/output/binary/linux-arm64/bin/step /usr/local/bin/
        ;;
esac
