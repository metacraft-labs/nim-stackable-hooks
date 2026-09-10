echo "PROBE: bash started pid=$$"
x=1
for i in 1 2 3; do x=$((x+i)); done
echo "NO_FORK_OK x=$x"
