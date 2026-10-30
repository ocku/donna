#!/bin/sh
set -eu

# Match Donna's UDP source-address policy: bind a concrete container IP.
if [ -z "${LISTEN_ADDR:-}" ]; then
    addresses=$(hostname -i)

    for address in $addresses; do
        case "$address" in
            *.*)
                LISTEN_ADDR="$address:5353"
                export LISTEN_ADDR
                break
                ;;
        esac
    done

    if [ -z "${LISTEN_ADDR:-}" ]; then
        echo 'adblock: no container IPv4 found; set LISTEN_ADDR explicitly' >&2
        exit 1
    fi
fi

exec /usr/local/bin/adblock "$@"
