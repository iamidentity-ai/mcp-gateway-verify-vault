#!/usr/bin/env bash
# Push main to BOTH remotes: the canonical public remote (origin) first, then
# the private internal mirror (the `mirror` remote — its URL lives in your local
# .git/config, never committed). CI runs on the canonical remote; the mirror is
# a mirror — never commit to it directly.
set -euo pipefail

git push origin main "$@"
git push mirror main "$@"
echo "release: pushed main to origin + mirror"
