#!/bin/bash
# ImWatching test suite.
# Usage: bash tests/run_tests.sh   (from anywhere)
# Scans the sample logs and the edge-case fixtures in tests/fixtures/ and
# checks the outputs. Never runs block mode for real - every check stays in
# dry run, so no iptables rule is ever added.
cd "$(dirname "$0")/.." || exit 1   # repo root

pass=0; fail=0
ok()  { pass=$((pass+1)); echo "ok   $1"; }
bad() { fail=$((fail+1)); echo "FAIL $1"; [ -n "$2" ] && printf '%s\n' "$2" | sed 's/^/     /'; }

# check_exact <name> <expected> <actual>
check_exact() {
  if [ "$2" = "$3" ]; then ok "$1"; else
    bad "$1" "--- expected ---"$'\n'"$2"$'\n'"--- got ---"$'\n'"$3"
  fi
}
# check_contains <name> <haystack> <needle>
check_contains() {
  if printf '%s\n' "$2" | grep -qF "$3"; then ok "$1"; else
    bad "$1" "missing: $3"$'\n'"--- got ---"$'\n'"$2"
  fi
}
# check_not_contains <name> <haystack> <needle>
check_not_contains() {
  if ! printf '%s\n' "$2" | grep -qF "$3"; then ok "$1"; else
    bad "$1" "should not contain: $3"$'\n'"--- got ---"$'\n'"$2"
  fi
}

T=tests/fixtures
# empty.log is generated here, not stored: it must stay a truly empty file
: > "$T/empty.log"

echo "== detect4.sh (one-shot scan) =="

# The two sample logs must reproduce the outputs we verified by hand.
out=$(./detect4.sh real_test.log)
check_exact "sample SSH log: verified report" \
"ALERT: 192.0.2.44 failed 6 times and then got IN
  [dry run] would block 192.0.2.44 with: iptables -A INPUT -s 192.0.2.44 -j DROP
BLOCK: 203.0.113.5 failed 6 times, never got in
  [dry run] would block 203.0.113.5 with: iptables -A INPUT -s 203.0.113.5 -j DROP" "$out"

out=$(./detect4.sh mixed_test.log)
check_exact "sample mixed log: verified report" \
"BLOCK: 198.51.100.9 failed 5 times, never got in
  [dry run] would block 198.51.100.9 with: iptables -A INPUT -s 198.51.100.9 -j DROP" "$out"

out=$(./detect4.sh "$T/empty.log"); rc=$?
check_exact "empty log: no output, exit 0" "0|" "$rc|$out"

out=$(./detect4.sh "$T/not_here.log" 2>&1); rc=$?
if [ "$rc" = 1 ] && printf '%s' "$out" | grep -q "cannot read"; then
  ok "missing log: friendly error, exit 1"
else
  bad "missing log: friendly error, exit 1" "rc=$rc out: $out"
fi

out=$(./detect4.sh "$T/invalid_ips.log")
check_exact "invalid octets (999.x, 300.x) ignored; valid attacker blocked" \
"BLOCK: 192.0.2.99 failed 5 times, never got in
  [dry run] would block 192.0.2.99 with: iptables -A INPUT -s 192.0.2.99 -j DROP" "$out"

out=$(./detect4.sh "$T/prefix_ips.log")
check_contains ".9 vs .99: 10.0.0.9 counted on its own"  "$out" "BLOCK: 10.0.0.9 failed 5 times"
check_contains ".9 vs .99: 10.0.0.99 counted on its own" "$out" "BLOCK: 10.0.0.99 failed 5 times"

out=$(./detect4.sh "$T/tricky_users.log")
check_contains    "fake IP in username: real source 10.1.1.1 blocked" "$out" "BLOCK: 10.1.1.1 failed 5 times"
check_not_contains "fake IP in username: 9.9.9.9 never blamed"        "$out" "9.9.9.9"
check_contains    "user named 'from': 10.2.2.2 still found"           "$out" "BLOCK: 10.2.2.2 failed 5 times"

out=$(./detect4.sh "$T/web_401_bytes.log")
check_exact "web 200 with byte-size 401 not counted; real 401s blocked" \
"BLOCK: 8.8.4.4 failed 5 times, never got in
  [dry run] would block 8.8.4.4 with: iptables -A INPUT -s 8.8.4.4 -j DROP" "$out"

out=$(./detect4.sh "$T/ok_first.log")
check_contains     "success BEFORE the fails: no ALERT (upgrade 4)" "$out" "BLOCK: 10.9.9.9 failed 5 times, never got in"
check_not_contains "success BEFORE the fails: old ALERT is gone"    "$out" "ALERT: 10.9.9.9"

out=$(./detect4.sh "$T/ok_middle.log")
check_contains     "success in the middle (before fail #5): no ALERT" "$out" "BLOCK: 10.8.8.8 failed 6 times, never got in"
check_not_contains "success in the middle: old ALERT is gone"         "$out" "ALERT: 10.8.8.8"

out=$(./detect4.sh "$T/ok_after.log")
check_contains     "success AFTER fail #5: ALERT (upgrade 4 keeps real alarms)" "$out" "ALERT: 10.9.9.10 failed 5 times and then got IN"

out=$(./detect4.sh "$T/inject_url.log"); rc=$?
check_exact "URL with 'Failed password from 9.9.9.9' in it: ignored (upgrade 3)" "0|" "$rc|$out"

out=$(./detect4.sh "$T/user_spray.log")
check_contains     "50 root fails from 50 IPs: WARN (upgrade 2)" "$out" "WARN: user 'root' failed 50 times from 50 different IPs"
check_not_contains "spray: no single IP hits 5 fails, so no BLOCK" "$out" "BLOCK:"

out=$(./detect4.sh "$T/user_spray_below.log")
check_exact "49 root fails from 49 IPs: under ULIMIT, quiet" "" "$out"

out=$(./detect4.sh "$T/no_ip.log"); rc=$?
check_exact "fail lines with no IP: no output, exit 0" "0|" "$rc|$out"

out=$(./detect4.sh mixed_test.log banana)
check_contains     "unknown mode stays a dry run"        "$out" "[dry run] would block 198.51.100.9"
check_not_contains "unknown mode never prints BLOCKED"   "$out" "BLOCKED 198.51.100.9"

if grep -q 'if \[ "$MODE" = "block" \]' detect4.sh && grep -q 'if \[ "$MODE" = "block" \]' watch.sh; then
  ok "iptables only runs when MODE is exactly 'block'"
else
  bad "iptables only runs when MODE is exactly 'block'" "guard line not found"
fi

d=$(mktemp -d); cp install.sh detect4.sh "$d"
( cd "$d" && HOME="$d" ./install.sh >/dev/null 2>&1 )
if cmp -s "$d/bin/login-detector" detect4.sh; then
  ok "install.sh installs the current detect4.sh as login-detector"
else
  bad "install.sh installs the current detect4.sh as login-detector"
fi
rm -rf "$d"

echo "== watch.sh (live watch) =="

# feed <dir> <lines...>: append lines to the live log with small gaps
feed() { local d=$1; shift; for l in "$@"; do printf '%s\n' "$l" >> "$d/live.log"; sleep 0.3; done; sleep 1; }
ssh_fail() { echo "Nov 17 10:50:0$2 srv sshd[1]: Failed password for root from $1 port 9$2 ssh2"; }

# 1) five fails then a success from the same IP: BLOCK, dry-run note, ALERT
d=$(mktemp -d); cp watch.sh "$d"; touch "$d/live.log"
( cd "$d" && exec timeout 10 ./watch.sh live.log > out.txt 2>&1 ) &
wpid=$!
sleep 1
feed "$d" "$(ssh_fail 203.0.113.60 1)" "$(ssh_fail 203.0.113.60 2)" "$(ssh_fail 203.0.113.60 3)" "$(ssh_fail 203.0.113.60 4)" "$(ssh_fail 203.0.113.60 5)"
feed "$d" "Nov 17 10:51:00 srv sshd[1]: Accepted password for root from 203.0.113.60 port 99 ssh2"
kill $wpid 2>/dev/null; wait $wpid 2>/dev/null
out=$(cat "$d/out.txt")
check_contains "5 fails from one IP: BLOCK"              "$out" "BLOCK 203.0.113.60 after 5 fails"
check_contains "dry run note printed"                    "$out" "[dry run] would block 203.0.113.60"
check_contains "blocked IP then gets IN: ALERT"          "$out" "ALERT 203.0.113.60 got IN after being blocked"
check_exact    "blocked IP saved to blocklist.txt"       "203.0.113.60" "$(cat "$d/blocklist.txt")"
check_contains "events also written to alerts.log"       "$(cat "$d/alerts.log")" "BLOCK 203.0.113.60 after 5 fails"
rm -rf "$d"

# 2) four fails: under the limit, nothing happens
d=$(mktemp -d); cp watch.sh "$d"; touch "$d/live.log"
( cd "$d" && exec timeout 8 ./watch.sh live.log > out.txt 2>&1 ) &
wpid=$!
sleep 1
feed "$d" "$(ssh_fail 203.0.113.61 1)" "$(ssh_fail 203.0.113.61 2)" "$(ssh_fail 203.0.113.61 3)" "$(ssh_fail 203.0.113.61 4)"
kill $wpid 2>/dev/null; wait $wpid 2>/dev/null
check_exact      "4 fails: no BLOCK"      "" "$(grep -c BLOCK "$d/out.txt" 2>/dev/null | grep -v '^0$' || true)"
check_not_contains "4 fails: blocklist stays empty" "$(cat "$d/blocklist.txt")" "203.0.113.61"
rm -rf "$d"

# 3) restart memory: a blocklisted IP is caught without any new fails
d=$(mktemp -d); cp watch.sh "$d"; touch "$d/live.log"; echo "203.0.113.70" > "$d/blocklist.txt"
( cd "$d" && exec timeout 8 ./watch.sh live.log > out.txt 2>&1 ) &
wpid=$!
sleep 1
feed "$d" "Nov 17 10:52:00 srv sshd[1]: Accepted password for root from 203.0.113.70 port 9 ssh2"
kill $wpid 2>/dev/null; wait $wpid 2>/dev/null
out=$(cat "$d/out.txt")
check_contains "restart: known attacker gets IN, ALERT right away" "$out" "ALERT 203.0.113.70 got IN after being blocked"
check_exact    "restart: blocklist not duplicated" "203.0.113.70" "$(cat "$d/blocklist.txt")"
rm -rf "$d"

# 4) [limit] half-counted fails do not survive a restart
d=$(mktemp -d); cp watch.sh "$d"; touch "$d/live.log"
( cd "$d" && exec timeout 8 ./watch.sh live.log > out.txt 2>&1 ) &
wpid=$!
sleep 1
feed "$d" "$(ssh_fail 203.0.113.80 1)" "$(ssh_fail 203.0.113.80 2)" "$(ssh_fail 203.0.113.80 3)" "$(ssh_fail 203.0.113.80 4)"
kill $wpid 2>/dev/null; wait $wpid 2>/dev/null; sleep 0.5
( cd "$d" && exec timeout 8 ./watch.sh live.log > out2.txt 2>&1 ) &
wpid=$!
sleep 1
feed "$d" "$(ssh_fail 203.0.113.80 5)"
kill $wpid 2>/dev/null; wait $wpid 2>/dev/null
out2=$(cat "$d/out2.txt")
check_contains "4 fails + restart + 1 fail in the window: BLOCKED (upgrade 1)" "$out2" "BLOCK 203.0.113.80 after 5 fails"
check_exact    "restart-count: blocklist holds the attacker" "203.0.113.80" "$(cat "$d/blocklist.txt")"
rm -rf "$d"

# 2b) fails older than the window do not count (upgrade 1)
d=$(mktemp -d); cp watch.sh "$d"; touch "$d/live.log"
oldts=$(( $(date +%s) - 3600 ))
for i in 1 2 3 4; do echo "$oldts 203.0.113.90" >> "$d/fails.db"; done
( cd "$d" && exec timeout 8 ./watch.sh live.log > out.txt 2>&1 ) &
wpid=$!
sleep 1
feed "$d" "$(ssh_fail 203.0.113.90 1)"
kill $wpid 2>/dev/null; wait $wpid 2>/dev/null
check_exact "4 fails from an hour ago + 1 now: NOT blocked (window works)" "" "$(cat "$d/blocklist.txt")"
check_exact "old fails got pruned, only the fresh one stays" "1" "$(grep -c '203.0.113.90' "$d/fails.db")"
rm -rf "$d"

# 5) invalid octets are not an attacker
d=$(mktemp -d); cp watch.sh "$d"; touch "$d/live.log"
( cd "$d" && exec timeout 8 ./watch.sh live.log > out.txt 2>&1 ) &
wpid=$!
sleep 1
feed "$d" "$(ssh_fail 999.9.9.9 1)" "$(ssh_fail 999.9.9.9 2)" "$(ssh_fail 999.9.9.9 3)" "$(ssh_fail 999.9.9.9 4)" "$(ssh_fail 999.9.9.9 5)" "$(ssh_fail 999.9.9.9 6)"
kill $wpid 2>/dev/null; wait $wpid 2>/dev/null
check_exact "999.9.9.9 x6: nothing blocked" "" "$(cat "$d/blocklist.txt")"
rm -rf "$d"

# 6) fake IP inside the username does not steal the blame (live)
d=$(mktemp -d); cp watch.sh "$d"; touch "$d/live.log"
( cd "$d" && exec timeout 10 ./watch.sh live.log > out.txt 2>&1 ) &
wpid=$!
sleep 1
feed "$d" \
  "Nov 17 10:53:01 srv sshd[1]: Failed password for invalid user 9.9.9.9 from 10.3.3.3 port 1 ssh2" \
  "Nov 17 10:53:02 srv sshd[1]: Failed password for invalid user 9.9.9.9 from 10.3.3.3 port 2 ssh2" \
  "Nov 17 10:53:03 srv sshd[1]: Failed password for invalid user 9.9.9.9 from 10.3.3.3 port 3 ssh2" \
  "Nov 17 10:53:04 srv sshd[1]: Failed password for invalid user 9.9.9.9 from 10.3.3.3 port 4 ssh2" \
  "Nov 17 10:53:05 srv sshd[1]: Failed password for invalid user 9.9.9.9 from 10.3.3.3 port 5 ssh2"
kill $wpid 2>/dev/null; wait $wpid 2>/dev/null
out=$(cat "$d/out.txt")
check_contains     "live: real source 10.3.3.3 blocked"    "$out" "BLOCK 10.3.3.3 after 5 fails"
check_not_contains "live: fake 9.9.9.9 never blamed"       "$out" "9.9.9.9"
check_exact        "live: blocklist holds the real source" "10.3.3.3" "$(cat "$d/blocklist.txt")"
rm -rf "$d"

# 6b) one username hammered from many IPs (upgrade 2)
d=$(mktemp -d); cp watch.sh "$d"; touch "$d/live.log"
( cd "$d" && exec timeout 10 ./watch.sh live.log > out.txt 2>&1 ) &
wpid=$!
sleep 1
for i in $(seq 1 50); do echo "Nov 17 10:55:01 srv sshd[1]: Failed password for root from 10.0.3.$i port 60$i ssh2"; done >> "$d/live.log"
sleep 2
kill $wpid 2>/dev/null; wait $wpid 2>/dev/null
out=$(cat "$d/out.txt")
check_contains "live: 50 root fails from 50 IPs: WARN (upgrade 2)" "$out" "WARN user root failed 50 times from 50 different IPs in 10 min"
check_exact    "live spray: no single IP blocked" "" "$(cat "$d/blocklist.txt")"
rm -rf "$d"

# 7) missing log: watcher says so and waits instead of crashing
d=$(mktemp -d); cp watch.sh "$d"
( cd "$d" && timeout 3 ./watch.sh live.log > out.txt 2> err.txt )
rc=$?
if [ "$rc" = 124 ] && grep -q "does not exist yet" "$d/err.txt"; then
  ok "missing log: clear note, keeps waiting for the file"
else
  bad "missing log: clear note, keeps waiting for the file" "rc=$rc err: $(cat "$d/err.txt")"
fi
rm -rf "$d"

echo
echo "passed: $pass   failed: $fail"
[ "$fail" = 0 ]
