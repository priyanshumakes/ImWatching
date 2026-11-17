# ImWatching

A small Bash tool that watches Linux log files, finds IP addresses that failed
to log in many times, and tells you which ones to worry about. It can scan a
saved log once, or watch a live log and react as new lines come in.

I built this to learn Bash and log analysis by hand. It is a learning project,
not a replacement for real tools like fail2ban.

## What it does

Two scripts:

- `detect4.sh` (one-shot scan): reads a whole log file (SSH, FTP, or web
  server logs) and counts failed logins per IP address. If an IP fails 5 or
  more times:
  - **BLOCK** - it never got in, so it looks like an attack
  - **ALERT** - it failed many times and then got IN, which is worse
- `watch.sh` (live watch): follows a growing log with `tail -F` and reacts to
  each new line. It remembers blocked IPs in `blocklist.txt`, so even after a
  restart it alerts the moment a known attacker gets in.

Both scripts default to dry-run mode: they only print what they *would* do.
In block mode they add a firewall rule with `iptables` to drop the IP.

## Install

```bash
git clone https://github.com/priyanshumakes/ImWatching.git
cd ImWatching
./install.sh
echo 'export PATH="$HOME/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

`install.sh` copies the scanner into `~/bin`. The `export` line adds that
folder to your PATH so you can run it from anywhere:

```bash
login-detector /path/to/logfile
```

## Usage

### One-shot scan

```bash
login-detector mixed_test.log          # dry run: report only, nothing blocked
login-detector mixed_test.log block    # block mode: actually adds iptables rules
```

Example output:

```
BLOCK: 198.51.100.9 failed 5 times, never got in
  [dry run] would block 198.51.100.9 with: iptables -A INPUT -s 198.51.100.9 -j DROP
ALERT: 192.0.2.44 failed 6 times and then got IN
  [dry run] would block 192.0.2.44 with: iptables -A INPUT -s 192.0.2.44 -j DROP
```

### Live watch

```bash
touch live.log
./watch.sh live.log          # dry run (default)
./watch.sh live.log block    # block mode: adds real iptables rules
```

`watch.sh` sits and waits for new lines. To test it, open a second terminal
and add log lines by hand:

```bash
echo "Nov 17 10:52:00 srv sshd[1]: Failed password for root from 203.0.113.50 port 9 ssh2" >> live.log
```

After 5 fails from the same IP it prints a BLOCK line, saves the IP to
`blocklist.txt`, and (in block mode) drops it with iptables. If that IP later
logs in successfully, you get the important one:

```
2026-11-17 10:52:00 ALERT 203.0.113.50 got IN after being blocked
```

Every event is also written to `alerts.log` with a timestamp.

Stop it with Ctrl+C. Because blocked IPs live in `blocklist.txt`, a restarted
`watch.sh` still knows old attackers: if a blocked IP gets in days later, it
alerts right away, without needing to see the fails again.

### Tip: timestamped alert log for one-shot scans

`detect4.sh` just prints to the screen. To save every alert with a timestamp,
pipe the output through a small loop:

```bash
./detect4.sh mixed_test.log | while read line; do echo "$(date '+%F %T') $line"; done >> alerts.log
```

## How it works (short version)

`detect4.sh`:

1. `grep -E` keeps only lines that look like a failed login. It knows three
   patterns: `Failed password` (SSH), `FAIL LOGIN` (FTP), and `" 401 ` (a
   real web status, not the byte size).
2. A small awk helper (`pick_ips`) pulls out the one IP each line talks
   about: the IP after the word "from" (SSH/FTP style), otherwise the first
   IP on the line (web style). It skips junk octets like 999.1.2.3.
3. For each IP, it counts the failures. 5 or more means act.
4. It checks the log again for a success pattern (`Accepted password`,
   `OK LOGIN`) from the same IP. Found = ALERT. Not found = BLOCK.
5. Blocking is done with `iptables -A INPUT -s <ip> -j DROP` - but only in
   block mode.

`watch.sh`:

1. On start it reads `blocklist.txt` into memory. This is its long-term
   memory of blocked IPs.
2. `tail -n 0 -F` follows only new lines added to the log from now on.
3. For each new line the same `pick_ips` helper pulls the IP, then the
   script keeps a running fail count per IP in a Bash associative array
   (`declare -A`).
4. At 5 fails it blocks the IP and appends it to `blocklist.txt`. A success
   line from a blocked IP triggers the ALERT.
5. A small `log()` function prints each event with a timestamp and saves it
   to `alerts.log` at the same time (`tee`).

All the patterns and the limit (5) are variables at the top of each script,
so adding a new program or changing the limit means editing one line.

## Files

- `detect4.sh` - the one-shot scanner
- `watch.sh` - the live watcher with memory
- `install.sh` - installs the scanner as the `login-detector` command in `~/bin`
- `real_test.log` - practice log with SSH lines only
- `mixed_test.log` - practice log mixing SSH, FTP and web server lines
- `blocklist.txt` - created by `watch.sh`, the memory of blocked IPs
- `alerts.log` - timestamped event log, one line per event
- `live.log` - your own growing log for watch mode (create it with `touch`)
- `tests/` - the test suite (`run_tests.sh`) and its fixture logs

## Tests

There is a test suite in `tests/`:

```bash
bash tests/run_tests.sh
```

It runs both scripts against the two sample logs and edge-case fixtures:
empty and missing logs, invalid IPs (999.x), look-alike IPs (10.0.0.9 vs
10.0.0.99), fake IPs inside usernames, web responses with 401 as the byte
size, watcher restarts, and more. 33 checks, all passing. Every check stays
in dry run - the suite never adds a real iptables rule.

## Honest limits

- The rules are simple. A real attacker who spreads attempts over days, or
  rotates IPs, will not be caught.
- Only three failure patterns are known: SSH, FTP (vsftpd style), and web 401.
  Other programs need a new line in `FAILPAT`.
- `watch.sh` counts fails only since it started. The blocklist survives a
  restart; half-counted fails do not.
- Block mode is untested on a live server. Dry run is the default for a
  reason - check the output before you trust it.
- Blocking is permanent until you remove the rule or reboot. There is no
  automatic unban.
- A success from an IP *anywhere* in the log counts as "got IN", even if
  the success came before the fails. Order is not checked.
- The scan trusts the log text. A web request whose URL contains the words
  `Failed password from 9.9.9.9` is still counted as a fail for 9.9.9.9
  (tests/fixtures/inject_url.log proves it). Real per-service log parsing is
  future work.

## License

MIT
