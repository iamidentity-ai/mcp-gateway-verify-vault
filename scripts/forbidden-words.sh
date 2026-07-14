#!/usr/bin/env bash
# Forbidden-words scan — this repo is customer-shareable. Internal demo names,
# tenants, hosts, and infrastructure details must never leak into it.
# CI runs this on every push; run locally with: npm run lint:words
set -euo pipefail

cd "$(dirname "$0")/.."

# Internal portfolio names + infrastructure that must not appear.
# NOTE: generic words like "insurance" are forbidden as DOMAIN names — the
# example domain here is "records". Add exceptions only with a comment.
# NOTE: the maintainer contact rgraham@us.ibm.com is an intentional, allowed
# email — do NOT add `rgraham` here. `github.ibm.com` (the internal mirror host)
# stays blocked so a mirror URL can never leak into a committed file.
PATTERN='insurance|banking|healthcare|concierge|copilot|watson|big blue|iia\b|demos\.verify\.ibm\.com|securemytechnology|ec2-user|44\.20[01]\.|34\.194\.|spire-server-demo|agenticai|Charlie|github\.ibm\.com'

MATCHES=$(grep -rniE "$PATTERN" \
  --include='*.ts' --include='*.js' --include='*.json' --include='*.md' \
  --include='*.sql' --include='*.sh' --include='*.yml' --include='*.yaml' \
  --exclude-dir=node_modules --exclude-dir=dist --exclude-dir=.git \
  . 2>/dev/null | grep -v 'scripts/forbidden-words.sh' || true)

if [[ -n "$MATCHES" ]]; then
  echo "FORBIDDEN WORDS FOUND — internal names must not appear in this repo:"
  echo "$MATCHES"
  exit 1
fi
echo "forbidden-words: clean"
