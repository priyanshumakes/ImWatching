#!/bin/bash
LOG=${1:-auth.log}
MODE=${2:-dry}
LIMIT=5
ULIMIT=50

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

# parse_logs reads log lines on stdin and prints one event per line:
#   "fail <ip> <user>"  - a real failed login (sshd, vsftpd, or web 401)
#   "ok <ip>"           - a real successful login (sshd, vsftpd)
# Everything else prints nothing. The line must fit the real log format, so
# text typed inside a URL or a username cannot fake a login event.
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

EVENTS=$(parse_logs < "$LOG")
FAILIPS=$(printf '%s\n' "$EVENTS" | awk '$1 == "fail" { print $2 }')

for ip in $(printf '%s\n' "$FAILIPS" | sort -u); do
  [ -z "$ip" ] && continue
  fails=$(printf '%s\n' "$FAILIPS" | grep -cFx "$ip")
  if [ "$fails" -ge "$LIMIT" ]; then
    limline=$(printf '%s\n' "$EVENTS" | awk -v ip="$ip" -v lim="$LIMIT" '$1 == "fail" && $2 == ip { n++; if (n == lim) { print NR; exit } }')
    if [ -n "$limline" ] && printf '%s\n' "$EVENTS" | tail -n +"$((limline + 1))" | awk -v ip="$ip" '$1 == "ok" && $2 == ip { f = 1 } END { exit !f }'; then
      echo "ALERT: $ip failed $fails times and then got IN"
    else
      echo "BLOCK: $ip failed $fails times, never got in"
    fi
    block_ip "$ip"
  fi
done

# one username hammered from many different IPs (attackers switching IPs)
printf '%s\n' "$EVENTS" | awk '$1 == "fail" && $3 != "-" { print $3 }' | sort -u | while read -r user; do
  [ -z "$user" ] && continue
  stats=$(printf '%s\n' "$EVENTS" | awk -v u="$user" '$1 == "fail" && $3 == u { n++; ips[$2] = 1 } END { print n, length(ips) }')
  ufails=${stats% *}; uips=${stats##* }
  if [ "$ufails" -ge "$ULIMIT" ]; then
    echo "WARN: user '$user' failed $ufails times from $uips different IPs"
  fi
done
