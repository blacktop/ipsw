#!/usr/bin/env bash

set -o errexit
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: run.sh KERNELCACHE_PATH

This script runs the generate.py script in "headless mode" IDA Pro.

'
    exit
fi


main() {
    KERNELCACHE_PATH="$1"
    echo "  🚀 Starting... $KERNELCACHE_PATH"
    # IDA Help: Command line switches - https://www.hex-rays.com/products/ida/support/idadoc/417.shtml
    /Applications/IDA\ Pro\ 8.4/ida64.app/Contents/MacOS/idat64 -A -P -S'generate/generate.py' -L/tmp/ida.log $KERNELCACHE_PATH
    echo "  🎉 Done!"
}

main "$@"
