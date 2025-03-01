#!/usr/bin/env bash
D=$(dirname $BASH_SOURCE)
if [ -z "$OUT" ]; then
  OUT=$D/bin${S}
fi
exec "$@" \
