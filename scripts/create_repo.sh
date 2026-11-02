#!/usr/bin/env bash
# Creates the git repository for this lab. The repo name = this folder's name (Lab01).
#   ./scripts/create_repo.sh                      -> local repo only
#   GITHUB_USER=you GITHUB_TOKEN=ghp_... ./scripts/create_repo.sh   -> also creates a PUBLIC GitHub repo and pushes
# The token needs the "repo" (classic) or "Administration: write + Contents: write" (fine-grained) permission.
set -euo pipefail
cd "$(dirname "$0")/.."
NAME="$(basename "$PWD")"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 || git init -q -b main
git config user.name  >/dev/null || { echo "Set identity first: git config --global user.name/user.email (Step 03)"; exit 1; }
# Safety: refuse to commit anything that looks like a credential.
if git ls-files -o -c --exclude-standard | xargs grep -lE 'AKIA[0-9A-Z]{16}|BEGIN (RSA |EC )?PRIVATE KEY|ghp_[A-Za-z0-9]{30,}' 2>/dev/null; then
  echo "STOP: the files above look like they contain credentials."; exit 1; fi
git add -A
git diff --cached --quiet || git commit -q -m "Lab01: Nimbus Identity Console (IAM lab)"
echo "Local repo ready: $PWD (branch $(git branch --show-current))"
if [ -n "${GITHUB_USER:-}" ] && [ -n "${GITHUB_TOKEN:-}" ]; then
  code=$(curl -s -o /tmp/gh.json -w '%{http_code}' -X POST https://api.github.com/user/repos \
    -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
    -d "{\"name\":\"$NAME\",\"description\":\"Cloud Security Lab01 - IAM on AWS free tier\",\"private\":false}")
  case "$code" in 201) echo "Created https://github.com/$GITHUB_USER/$NAME";; 422) echo "Repo already exists - reusing it";; *) cat /tmp/gh.json; exit 1;; esac
  git remote get-url origin >/dev/null 2>&1 || git remote add origin "https://github.com/$GITHUB_USER/$NAME.git"
  AUTH=$(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 -w0)
  git -c http.extraheader="Authorization: Basic $AUTH" push -u origin main
  echo "Pushed. Clone URL for script 04: https://github.com/$GITHUB_USER/$NAME.git"
else
  echo "No GITHUB_USER/GITHUB_TOKEN set: create an empty PUBLIC repo named '$NAME' on GitHub, then:"
  echo "  git remote add origin https://github.com/<you>/$NAME.git && git push -u origin main"
fi
