#!/usr/bin/env bash

set -o errexit
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

: ${IDA_PLUGIN_FOLDER:=$HOME/.idapro/plugins/}

if [[ "${1-}" =~ ^-*h(elp)?$ ]]; then
    echo 'Usage: install.sh IDA_PLUGIN

This script installs an IDA Pro plugin.
'
    exit
fi


main() {
    IDA_PLUGIN_FILE="$1"
    echo "  🚀 Installing $IDA_PLUGIN_FILE to $IDA_PLUGIN_FOLDER"
    cp $IDA_PLUGIN_FILE $IDA_PLUGIN_FOLDER
    echo "  🎉 Done!"
}

main "$@"
