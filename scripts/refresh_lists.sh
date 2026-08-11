#!/usr/bin/env bash

set -euo pipefail

BLOCK_URL="https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/domains/ultimate.txt"

ALLOW_URLS=(
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/ultimate-known-issues.txt"
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/microsoft.txt"
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/facebook.txt"
  "https://raw.githubusercontent.com/hagezi/dns-blocklists/refs/heads/main/share/apple-private-relay.txt"
)

tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

# download fetches a single URL into a file. Without --fail, curl exits successfully and writes the
# error page body (e.g. "404: Not Found") to the output file, which would then be committed as the
# new list. With it, a missing source aborts the run and leaves the existing lists in place.
download() {
  local url="$1"
  local dest="$2"

  if ! curl -sS --fail --location --retry 3 --retry-delay 5 --retry-all-errors -o "${dest}" "${url}"; then
    echo "error: failed to download ${url}" >&2
    return 1
  fi
}

# Download the block list.
download "${BLOCK_URL}" "${tmp_dir}/block.txt"

# Download and merge allow lists + known issues. Each URL is fetched individually so that one
# missing source fails the run instead of quietly producing a shorter allow list.
for url in "${ALLOW_URLS[@]}"; do
  download "${url}" "${tmp_dir}/allow-part.txt"
  cat "${tmp_dir}/allow-part.txt" >> "${tmp_dir}/allow.txt"
done

# Every source downloaded successfully, so replace the embedded lists.
mv "${tmp_dir}/block.txt" internal/list/data/block.txt
mv "${tmp_dir}/allow.txt" internal/list/data/allow.txt
