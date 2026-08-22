#!/usr/bin/env bash
# Build the Director console and place it where the Python service serves it.
#
# Run before `gcloud run deploy scf-director`. The output lands in
# src/scf/app/console/ rather than web/dist/ because git ignores dist and an
# ignored directory does not reliably reach a Cloud Run build context.
set -euo pipefail
cd "$(dirname "$0")/.."

npm --prefix web ci
npm --prefix web run build

rm -rf src/scf/app/console
cp -r web/dist src/scf/app/console
echo "console built -> src/scf/app/console ($(find src/scf/app/console -type f | wc -l) files)"
