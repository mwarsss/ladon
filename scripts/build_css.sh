#!/usr/bin/env sh
# Builds web/tailwind.css for the scenario dashboard (no third-party script at runtime).
set -e
cd "$(dirname "$0")/.."
npx --yes tailwindcss@3.4.17 -c tailwind.config.js -i web/tailwind.input.css -o web/tailwind.css --minify
