#!/usr/bin/env bash
set -euo pipefail
cd /home/mac/workspace2/bitdash-auth-local
nohup node server.js >> /home/mac/workspace2/bitdash-auth-local/server.log 2>&1 &
