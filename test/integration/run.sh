#!/usr/bin/env bash
# Usage: test/integration/run.sh <scratch-dir>   — launches VS Code with an isolated profile
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="${1:?scratch dir}"
rm -rf "$TMP/ud" "$TMP/ext"; mkdir -p "$TMP/ud" "$TMP/ext"
code --user-data-dir "$TMP/ud" --extensions-dir "$TMP/ext" --disable-extensions --new-window \
  --extensionDevelopmentPath="$ROOT" --extensionTestsPath="$ROOT/test/integration/suite.js" --wait
