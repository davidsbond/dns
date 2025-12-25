#!/usr/bin/env bash

set -ex

# Download block list
curl -sS -L -o internal/list/data/block.txt https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/domains/ultimate.txt

# Download and merge allow lists + known issues
curl -sS -L -o - \
  https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/ultimate-known-issues.txt \
  https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/microsoft.txt \
  https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/facebook.txt \
  https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/apple-private-relay.txt \
  > internal/list/data/allow.txt
