#!/bin/sh
set -eu

fail() {
    printf 'donna-server: %s\n' "$*" >&2
    exit 1
}

# Explicit arguments expose the ordinary CLI, including check and --help.
if [ "$#" -gt 0 ]; then
    exec /usr/local/bin/donna "$@"
fi

if [ -n "${DONNA_CONFIG:-}" ]; then
    config_path=$DONNA_CONFIG
else
    role=${DONNA_ROLE:-recursive}
    case "$role" in
        forward|recursive|authoritative) ;;
        *) fail 'DONNA_ROLE must be forward, recursive, or authoritative' ;;
    esac

    listen_ip=${DONNA_LISTEN_IP:-}
    if [ -z "$listen_ip" ]; then
        # UDP must bind a concrete local address to preserve reply source IPs.
        addresses=$(hostname -i) || fail 'cannot detect container IP; set DONNA_LISTEN_IP'
        for address in $addresses; do
            case "$address" in
                *.*) listen_ip=$address; break ;;
            esac
        done
    fi
    [ -n "$listen_ip" ] || fail 'no IPv4 address found; set DONNA_LISTEN_IP'
    case "$listen_ip" in
        *[!0123456789abcdefABCDEF:.]*) fail 'DONNA_LISTEN_IP must be a numeric IP address' ;;
    esac

    port=${DONNA_PORT:-5353}
    case "$port" in
        *[!0-9]*|'') fail 'DONNA_PORT must be numeric' ;;
    esac
    case "$listen_ip" in
        *:*) listen_address="[$listen_ip]:$port" ;;
        *) listen_address="$listen_ip:$port" ;;
    esac

    # An unset ACL permits loopback only. An explicitly empty ACL denies all.
    networks=${DONNA_RECURSION_CIDRS-127.0.0.0/8,::1/128}
    case "$networks" in
        *[!0123456789abcdefABCDEF:.,/]*) fail 'DONNA_RECURSION_CIDRS must be comma-separated numeric CIDRs without spaces' ;;
    esac
    acl=
    if [ -n "$networks" ]; then
        acl=$(printf '"%s"' "$networks" | sed 's/,/","/g')
    fi

    upstream=${DONNA_UPSTREAM:-1.1.1.1:53}
    invalid_upstream=$(printf '%s' "$upstream" | tr -d '0123456789abcdefABCDEF:.[]')
    [ -z "$invalid_upstream" ] || fail 'DONNA_UPSTREAM must be a numeric socket address'

    config_dir=$(mktemp -d /tmp/donna.XXXXXX)
    config_path=$config_dir/donna.toml
    sed \
        -e "s|@LISTEN_ADDRESS@|$listen_address|g" \
        -e "s|@RECURSION_CIDRS@|$acl|g" \
        -e "s|@UPSTREAM@|$upstream|g" \
        "/usr/share/donna/config/$role.toml" > "$config_path"
fi

/usr/local/bin/donna check -c "$config_path"
exec /usr/local/bin/donna serve -c "$config_path"
