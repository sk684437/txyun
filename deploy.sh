#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PROJECT_NAME="${PROJECT_NAME:-edgeone-ws}"
EDGEONE_ENV="${EDGEONE_ENV:-production}"   # production | preview
EDGEONE_SITE="${EDGEONE_SITE:-global}"    # global | china

echo "Deploying EdgeOne Makers project"
echo "Directory: $SCRIPT_DIR"
echo "Project:   $PROJECT_NAME"
echo "Env:       $EDGEONE_ENV"
echo "Site:      $EDGEONE_SITE"

if ! command -v edgeone >/dev/null 2>&1; then
  echo "Error: edgeone CLI is not installed or not in PATH." >&2
  echo "Install it with: npm install -g edgeone" >&2
  exit 1
fi

echo "CLI version: $(edgeone -v 2>/dev/null || echo unknown)"

if command -v npm >/dev/null 2>&1 && [[ -f package-lock.json ]]; then
  npm ci
  npm run check
fi

edgeone makers deploy . \
  --name "$PROJECT_NAME" \
  --env "$EDGEONE_ENV" \
  --site "$EDGEONE_SITE"
