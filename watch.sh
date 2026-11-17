#!/bin/bash
LOG=${1:-live.log}
MODE=${2:-dry}
LIMIT=5
ULIMIT=50
WINDOW=600
FAILSDB=fails.db

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

# parse_logs: same idea as in detect4.sh - one log line in, one event out
# ("fail <ip> <user>" or "ok <ip>"), only when the line fits a real log
# format. Text inside a URL or username cannot fake an event.
parse_logs() {
  awk '
    function valid_ip(ip,   n, a, i) {
      n = split(ip, a, "[.]")
      if (n != 4) return 0
      for (i = 1; i <= 4; i++)
        if (a[i] !~ /^[0-9]+$/ || a[i] + 0 > 255) return 0
      return 1
    }
    # sshd: Nov 17 09:01:10 srv sshd[1201]: Failed password for root from 203.0.113.5 port 52114 ssh2
    # The LAST " from <ip> port <n> " wins: in a real sshd line the source
    # always comes after the username, so a fake address typed inside the
    # username cannot steal the blame.
    /sshd\[[0-9]+\]: (Failed|Accepted) password for / {
      kind = ($0 ~ /sshd\[[0-9]+\]: Failed password for /) ? "fail" : "ok"
      ip = ""; fromidx = 0
      for (i = NF; i >= 1; i--) {
        if ($i == "from" && i + 3 <= NF && $(i+2) == "port" && $(i+3) ~ /^[0-9]+$/ && valid_ip($(i+1))) { ip = $(i+1); fromidx = i; break }
      }
      if (ip == "") next
      foridx = 0
      for (i = 1; i < fromidx; i++) if ($i == "for") foridx = i
      user = ""
      for (i = foridx + 1; i < fromidx; i++) user = (user == "") ? $i : user "_" $i
      if (user ~ /^invalid_user_/) sub(/^invalid_user_/, "", user)
      else if (user == "invalid_user" || user == "") user = "-"
      print kind, ip, user
      next
    }
    # vsftpd: Nov 17 10:02:01 srv vsftpd: FAIL LOGIN: Client "198.51.100.9"
    # Last match wins too.
    /(FAIL|OK) LOGIN: Client "/ {
      line = $0; ip = ""
      while (match(line, /(FAIL|OK) LOGIN: Client "/)) {
        k = (substr(line, RSTART, 4) == "FAIL") ? "fail" : "ok"
        line = substr(line, RSTART + RLENGTH)
        q = index(line, "\"")
        if (q > 1 && valid_ip(substr(line, 1, q - 1))) { ip = substr(line, 1, q - 1); kind = k }
      }
      if (ip != "") print kind, ip, "-"
      next
    }
    # web combined log: the client IP is the first word and a failed login is
    # a real 401 in the status slot: 198.51.100.9 - - [..] "POST /login HTTP/1.1" 401 512
    {
      split($0, w, " ")
      if (valid_ip(w[1]) && $0 ~ /" 401 /) print "fail", w[1], "-"
    }'
}

declare -A blocked
declare -A uwarned
touch blocklist.txt "$FAILSDB"
while read -r saved; do blocked[$saved]=1; done < blocklist.txt

# fails.db keeps one "epoch ip user" line per failed login, so counts survive
# a restart. On start, forget the fails that are older than WINDOW seconds.
now=$(date +%s)
awk -v cut=$((now - WINDOW)) '$1 >= cut' "$FAILSDB" > "$FAILSDB.tmp" && mv "$FAILSDB.tmp" "$FAILSDB"

tail -n 0 -F "$LOG" | while read -r line; do
  ev=$(printf '%s\n' "$line" | parse_logs)
  [ -z "$ev" ] && continue
  kind=${ev%% *}
  rest=${ev#* }
  ip=${rest%% *}
  user=${rest#* }
  if [ "$kind" = "fail" ]; then
    now=$(date +%s)
    echo "$now $ip $user" >> "$FAILSDB"
    awk -v cut=$((now - WINDOW)) '$1 >= cut' "$FAILSDB" > "$FAILSDB.tmp" && mv "$FAILSDB.tmp" "$FAILSDB"
    count=$(awk -v ip="$ip" '$2 == ip { n++ } END { print n + 0 }' "$FAILSDB")
    if [ "$count" -ge "$LIMIT" ] && [ -z "${blocked[$ip]}" ]; then
      blocked[$ip]=1
      echo "$ip" >> blocklist.txt
      log "BLOCK $ip after $count fails in $((WINDOW / 60)) min"
      block_ip "$ip"
    fi
    if [ "$user" != "-" ]; then
      ustats=$(awk -v u="$user" '$3 == u { n++; ips[$2] = 1 } END { print n, length(ips) }' "$FAILSDB")
      ufails=${ustats% *}; uips=${ustats##* }
      if [ "$ufails" -ge "$ULIMIT" ] && [ -z "${uwarned[$user]}" ]; then
        uwarned[$user]=1
        log "WARN user $user failed $ufails times from $uips different IPs in $((WINDOW / 60)) min"
      fi
    fi
  elif [ "$kind" = "ok" ] && [ -n "${blocked[$ip]}" ]; then
    log "ALERT $ip got IN after being blocked"
  fi
done
