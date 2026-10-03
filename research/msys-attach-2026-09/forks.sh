#!/usr/bin/env bash
echo "PROBE: bash started pid=$$"
for ((i = 1; i <= 10; i++)); do
  x=$(/usr/bin/grep -c cmd /dev/null)
done
echo "TEN_FORKS_OK x=$x"
