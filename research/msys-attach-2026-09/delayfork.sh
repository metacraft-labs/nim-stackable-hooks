echo "PROBE: bash started pid=$$ SECONDS=$SECONDS"
while (( SECONDS < 3 )); do :; done      # pure builtin spin, no fork
echo "PROBE: spin done, forking now"
for i in 1 2 3 4 5 6 7 8 9 10; do x=$(/usr/bin/grep -c cmd /dev/null); done
echo "TEN_FORKS_OK x=$x"
