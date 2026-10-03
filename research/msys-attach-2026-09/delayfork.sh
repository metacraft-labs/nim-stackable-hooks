#!/usr/bin/env bash
echo "PROBE: bash started pid=$$ SECONDS=$SECONDS"
while (( SECONDS < 3 )); do :; done      # pure builtin spin, no fork
echo "PROBE: spin done, forking now"
for ((i = 1; i <= 10; i++)); do x=$(/usr/bin/grep -c cmd /dev/null); done
echo "TEN_FORKS_OK x=$x"
