set -e
n=0
for i in $(seq 1 25); do
  a=$(echo "x$i" | /usr/bin/tr 'x' 'y')
  b=$( ( /usr/bin/printf '%s\n' "$a" | /usr/bin/sed 's/y/z/' ) )
  c=$(/usr/bin/grep -c . /dev/null || true)
  n=$((n+1))
done
( cd /tmp && /usr/bin/ls >/dev/null )
echo "HEAVY_OK iterations=$n last=$b"
