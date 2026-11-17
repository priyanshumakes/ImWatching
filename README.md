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
  - **WARN** - one username failed 50+ times across many different IPs,
  which catches attackers who keep switching IPs
- `watch.sh` (live watch): follows a growing log with `tail -F` and reacts to
  each new line. It counts fails inside a 10 minute window, kept in
  `fails.db`, so a restart no longer resets the count. It remembers blocked
  IPs in `blocklist.txt`, so even after a restart it alerts the moment a
  known attacker gets in.

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

1. An awk helper (`parse_logs`) reads each line and only accepts real log
   formats: sshd lines (`sshd[pid]: Failed/Accepted password for ... from
   <ip> port <n>`), vsftpd lines (`FAIL/OK LOGIN: Client "<ip>"`), and web
   combined logs (valid IP as the first word plus a real `" 401 ` status).
   Anything else is ignored, so text inside a URL or a username can no
   longer fake a login event. For sshd, the LAST ` from <ip> port ` wins:
   in a real line the source comes after the username, so a fake address
   inside the username cannot steal the blame. Junk octets like 999.1.2.3
   are skipped.
2. For each IP, it counts the failures. 5 or more means act.
3. It checks the parsed events for a success from the same IP *after the
   5th fail*. Success after = ALERT (the attacker got in). No success
   after = BLOCK. A success that came before the fails does not raise the
   alarm.
4. It also counts fails per username across all IPs. One username with 50+
   fails from many different IPs prints a WARN, which catches IP switching.
5. Blocking is done with `iptables -A INPUT -s <ip> -j DROP` - but only in
   block mode.

`watch.sh`:

1. On start it reads `blocklist.txt` into memory (long-term memory of
   blocked IPs) and prunes `fails.db`, its running memory of failed logins:
   one "epoch ip user" line per fail, kept only for the last `WINDOW`
   seconds (default 600 = 10 minutes).
2. `tail -n 0 -F` follows only new lines added to the log from now on.
3. Each new line goes through the same `parse_logs` helper as the scanner.
   A fail appends the current time, IP and username to `fails.db`; the
   count is how many of that IP's fails fall inside the window. Because
   the counts live in a file, a restart does not reset them.
4. At 5 fails inside the window it blocks the IP and appends it to
   `blocklist.txt`. A success line from a blocked IP triggers the ALERT.
   It also watches per username: 50+ fails for one name from many
   different IPs inside the window prints a WARN (once per run).
5. A small `log()` function prints each event with a timestamp and saves it
   to `alerts.log` at the same time (`tee`).

The limits are variables at the top of each script: `LIMIT` (5 fails per
IP), `WINDOW` (600 seconds, watch only) and `ULIMIT` (50 fails per
username). Adding a new log format means adding one rule to `parse_logs`.

## Files

- `detect4.sh` - the one-shot scanner
- `watch.sh` - the live watcher with memory
- `install.sh` - installs the scanner as the `login-detector` command in `~/bin`
- `real_test.log` - practice log with SSH lines only
- `mixed_test.log` - practice log mixing SSH, FTP and web server lines
- `blocklist.txt` - created by `watch.sh`, the memory of blocked IPs
- `fails.db` - created by `watch.sh`, recent fails as "epoch ip user" lines
  (the 10 minute window)
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
10.0.0.99), fake IPs inside usernames, fake login text inside a URL, web
responses with 401 as the byte size, watcher restarts, window decay, the
order of successes and fails, and username sprays (one name, many IPs).
45 checks, all passing. Every check stays in dry run - the suite never
adds a real iptables rule.

## Honest limits

- Only three log formats are understood: sshd with a pid bracket
  (`sshd[123]:`), vsftpd, and web combined logs. Other daemons or other
  sshd flavors (no pid bracket, OpenSSH debug output) need a new rule in
  `parse_logs`.
- The WARN for username sprays only warns - it does not block anything,
  and it only counts usernames it can read from sshd lines. Names with
  spaces show with underscores.
- Block mode is untested on a live server. Dry run is the default for a
  reason - check the output before you trust it.
- Blocking is permanent until you remove the rule or reboot. There is no
  automatic unban.
- Everything runs as whoever runs the script. Someone with write access to
  the log or the state files can hide their tracks or fake an attacker.
- Guessing slower than 5 fails per 10 minutes per IP still slips through -
  that is the trade-off of the time window. Raise `WINDOW` in `watch.sh`
  for a longer memory. In the one-shot scan, an ALERT only means a success
  came after the 5th fail; a success between earlier fails reports as
  BLOCK.

## License

MIT
