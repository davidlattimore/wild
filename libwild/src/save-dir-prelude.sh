#!/usr/bin/env bash
D=$(dirname $BASH_SOURCE)
if [ -z "$OUT" ]; then
  OUT=$D/bin${S}
fi
L=()
has_double_dash=false
for arg in "$@"; do
  if [[ "$arg" == "--" ]]; then
    has_double_dash=true
    break
  fi
done
if $has_double_dash; then
  for arg in "$@"; do
    L+=("$arg")
    [[ "$arg" == "--" ]] && break
  done
else
  [[ $# -gt 0 ]] && L=("$1")
fi
for ((i = 0; i < ${#L[@]}; i++)); do
  shift
done
