#!/bin/sh
set -eu
cd /work
dnssec-keygen -q -a ECDSAP256SHA256 -n ZONE example.test.
dnssec-keygen -q -a ECDSAP256SHA256 -n ZONE -f KSK example.test.
dnssec-signzone -q -S -n 1 -s now-3600 -e now+86400 -N keep \
    -o example.test. -f nsec.db zone.db
dnssec-signzone -q -S -n 1 -s now-3600 -e now+86400 -N keep \
    -3 A1B2 -A -o example.test. -f nsec3.db zone.db
