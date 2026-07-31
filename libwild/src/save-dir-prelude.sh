#!/usr/bin/env bash
D=$(dirname $BASH_SOURCE)
if [ -z "$OUT" ]; then
  OUT=$D/bin${S}
fi
L=()
last_double_dash_index=0
for ((i = $#; i > 1; i--)); do
  if [[ "${!i}" == "--" ]]; then
    last_double_dash_index=$i
    break
  fi
done
if [[ $last_double_dash_index -gt 0 ]]; then
  for ((i = 1; i < last_double_dash_index; i++)); do
    L+=("$1")
    shift
  done
  shift
else
  while [ $# -gt 0 ]; do
    L+=("$1")
    shift
  done
fi
