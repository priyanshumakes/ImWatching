#!/bin/bash
mkdir -p "$HOME/bin"
cp detect4.sh "$HOME/bin/login-detector"
chmod +x "$HOME/bin/login-detector"
echo "Installed. Run it with: login-detector /path/to/logfile"
