#!/bin/bash
LOG=${1:-auth.log}
MODE=${2:-dry}
LIMIT=5
FAILPAT='Failed password|FAIL LOGIN|" 401 '
OKPAT='Accepted password|OK LOGIN'
IPPAT='[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'

if [ ! -r "$LOG" ]; then
  echo "error: cannot read log file: $LOG" >&2
  exit 1
fi

block_ip() {
  if [ "$MODE" = "block" ]; then
    sudo iptables -A INPUT -s "$1" -j DROP && echo "  BLOCKED $1"
  else
    echo "  [dry run] would block $1 with: iptables -A INPUT -s $1 -j DROP"
  fi
}

# pick_ips reads log lines on stdin and prints one IP per line: the IP after
# the word "from" (SSH/FTP style) when there is one, otherwise the first IP
# on the line (web style). Octets above 255 are skipped, and an IP glued to
# more digits or dots (10.0.0.9 inside 10.0.0.99) is not picked apart.
pick_ips() {
  IPPAT="$IPPAT" awk '
    function valid_ip(ip,   n, a, i) {
      n = split(ip, a, "[.]")
      if (n != 4) return 0
      for (i = 1; i <= 4; i++)
        if (a[i] !~ /^[0-9]+$/ || a[i] + 0 > 255) return 0
      return 1
    }
    {
      re = ENVIRON["IPPAT"]
      if (match($0, /from /)) {
        rest = substr($0, RSTART + 5)
        if (match(rest, re)) {
          cand = substr(rest, RSTART, RLENGTH)
          after = substr(rest, RSTART + RLENGTH, 1)
          if (valid_ip(cand) && after !~ /[0-9.]/) { print cand; next }
        }
      }
      start = 1
      while (match(substr($0, start), re)) {
        pos = start + RSTART - 1
        cand = substr($0, pos, RLENGTH)
        before = (pos > 1) ? substr($0, pos - 1, 1) : " "
        after = substr($0, pos + RLENGTH, 1)
        if (valid_ip(cand) && before !~ /[0-9.]/ && after !~ /[0-9.]/) { print cand; next }
        start = pos + 1
      }
    }'
}

FAILLINES=$(grep -E "$FAILPAT" "$LOG")
IPS=$(printf '%s\n' "$FAILLINES" | pick_ips)

for ip in $(printf '%s\n' "$IPS" | sort -u); do
  [ -z "$ip" ] && continue
  fails=$(printf '%s\n' "$IPS" | grep -cFx "$ip")
  if [ "$fails" -ge "$LIMIT" ]; then
    if grep -E "$OKPAT" "$LOG" | grep -qFw "$ip"; then
      echo "ALERT: $ip failed $fails times and then got IN"
    else
      echo "BLOCK: $ip failed $fails times, never got in"
    fi
    block_ip "$ip"
  fi
done
