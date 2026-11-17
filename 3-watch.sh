#!/bin/bash
LOG=${1:-live.log}
MODE=${2:-dry}
LIMIT=5
FAILPAT='Failed password|FAIL LOGIN|" 401 '
OKPAT='Accepted password|OK LOGIN'
IPPAT='[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'

if [ ! -f "$LOG" ]; then
  echo "note: $LOG does not exist yet - waiting for it to appear" >&2
fi

log() { echo "$(date '+%F %T') $1" | tee -a alerts.log; }

block_ip() {
  if [ "$MODE" = "block" ]; then
    sudo iptables -A INPUT -s "$1" -j DROP && log "  BLOCKED $1"
  else
    log "  [dry run] would block $1"
  fi
}

# pick_ips: same idea as in detect4.sh - one line in, the IP it talks about
# out (the IP after "from" when present, else the first IP). Junk octets like
# 999.1.2.3 are skipped.
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

declare -A fails
declare -A blocked
touch blocklist.txt
while read -r saved; do blocked[$saved]=1; done < blocklist.txt

tail -n 0 -F "$LOG" | while read -r line; do
  ip=$(printf '%s\n' "$line" | pick_ips)
  [ -z "$ip" ] && continue
  if printf '%s\n' "$line" | grep -qE "$FAILPAT"; then
    fails[$ip]=$(( ${fails[$ip]:-0} + 1 ))
    if [ "${fails[$ip]}" -ge "$LIMIT" ] && [ -z "${blocked[$ip]}" ]; then
      blocked[$ip]=1
      echo "$ip" >> blocklist.txt
      log "BLOCK $ip after ${fails[$ip]} fails"
      block_ip "$ip"
    fi
  elif printf '%s\n' "$line" | grep -qE "$OKPAT" && [ -n "${blocked[$ip]}" ]; then
    log "ALERT $ip got IN after being blocked"
  fi
done
