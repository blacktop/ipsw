#!/usr/bin/env bash

set -o errexit
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

# : ${TARGET:=}
# : ${MAX_VERSION:=}
# : ${MIN_VERSION:=}
# : ${PKL_FILE:=}

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: run.sh KERNELCACHE_PATH

This script runs the generate.py script in "headless mode" IDA Pro.

[SUPPORTED ENVIRONMENT VARIABLES]
    TARGET: The target binary. (e.g. com.apple.driver.AppleHIDKeyboard)
    MAX_VERSION: The maximum version of the target binary.
    MIN_VERSION: The minimum version of the target binary.
    PKL_FILE: The path to the pickle file. (e.g. /path/to/sig.pkl)

'
    exit
fi


main() {
    KERNELCACHE_PATH="$1"
    echo "  🚀 Starting... $KERNELCACHE_PATH"
    # IDA Help: Command line switches - https://www.hex-rays.com/products/ida/support/idadoc/417.shtml
    /Applications/IDA\ Pro\ 8.4/ida64.app/Contents/MacOS/idat64 -A -P -S"generate/generate.py" -L/tmp/ida.log $KERNELCACHE_PATH
    echo "  🎉 Done!"
}

main "$@"
