#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
if [[ "${TRACE-0}" == "1" ]]; then
    set -o xtrace
fi

# utility functions
INFO() {
    /bin/echo -e "\e[104m\e[97m[INFO]\e[49m\e[39m $@"
}

WARNING() {
    /bin/echo >&2 -e "\e[101m\e[97m[WARNING]\e[49m\e[39m $@"
}

ERROR() {
    /bin/echo >&2 -e "\e[101m\e[97m[ERROR]\e[49m\e[39m $@"
}

# constants
SYSTEMD_UNIT="ipsw.service"
# global vars
BIN=""
SYSTEMD=""
CFG_DIR=""
XDG_RUNTIME_DIR_CREATED=""

# run checks and also initialize global vars
init() {
    # OS verification: Linux only
    case "$(uname)" in
    Linux) ;;

    *)
        ERROR "ipswd cannot be installed on $(uname)"
        exit 1
        ;;
    esac
    # set SYSTEMD
    if systemctl --user show-environment >/dev/null 2>&1; then
        SYSTEMD=1
    fi
    # HOME verification
    if [ -z "${HOME:-}" ] || [ ! -d "$HOME" ]; then
        ERROR "HOME needs to be set"
        exit 1
    fi
    if [ ! -w "$HOME" ]; then
        ERROR "HOME needs to be writable"
        exit 1
    fi
    # set CFG_DIR
    CFG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}"
    # Validate XDG_RUNTIME_DIR and set XDG_RUNTIME_DIR_CREATED
    if [ -z "${XDG_RUNTIME_DIR:-}" ] || [ ! -w "$XDG_RUNTIME_DIR" ]; then
        if [ -n "$SYSTEMD" ]; then
            ERROR "Aborting because systemd was detected but XDG_RUNTIME_DIR (\"$XDG_RUNTIME_DIR\") is not set, does not exist, or is not writable"
            ERROR "Hint: this could happen if you changed users with 'su' or 'sudo'. To work around this:"
            ERROR "- try again by first running with root privileges 'loginctl enable-linger <user>' where <user> is the unprivileged user and export XDG_RUNTIME_DIR to the value of RuntimePath as shown by 'loginctl show-user <user>'"
            ERROR "- or simply log back in as the desired unprivileged user (ssh works for remote machines, machinectl shell works for local machines)"
            exit 1
        fi
        export XDG_RUNTIME_DIR="$HOME/.ipsw/run"
        mkdir -p -m 700 "$XDG_RUNTIME_DIR"
        XDG_RUNTIME_DIR_CREATED=1
    fi
}

# CLI subcommand: "uninstall"
cmd_uninstall() {
    # requirements are already checked in init()
    if [ -z "$SYSTEMD" ]; then
        INFO "systemd not detected, ${SYSTEMD_UNIT} needs to be stopped manually:"
    else
        unit_file="${CFG_DIR}/systemd/user/${SYSTEMD_UNIT}"
        (
            set -x
            systemctl --user stop "${SYSTEMD_UNIT}"
        ) || :
        (
            set -x
            systemctl --user disable "${SYSTEMD_UNIT}"
        ) || :
        rm -f "${unit_file}"
        INFO "Uninstalled ${SYSTEMD_UNIT}"
    fi

    unset IPSW_DAEMON_HOST
    unset IPSW_DAEMON_PORT
    unset IPSW_DAEMON_SOCKET

    INFO 'Configured CLI use the "default" context.'
    INFO
    INFO 'Make sure to unset or update the environment PATH, IPSW_DAEMON_HOST, IPSW_DAEMON_PORT or IPSW_DAEMON_SOCKET environment variables if you have added them to `~/.bashrc`.'
    INFO "This uninstallation tool does NOT remove ipswd binaries and data."
    INFO "To remove data, run: \`rm -rf $HOME/.local/share/ipswd\`"
}

main() {
    init
    cmd_uninstall
    echo "  🎉 Done!"
}

main "$@"
