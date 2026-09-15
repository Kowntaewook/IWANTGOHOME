#!/usr/bin/env sh
set -eu

umask 077
exec python3 /opt/finder/docker/runtime.py "$@"
