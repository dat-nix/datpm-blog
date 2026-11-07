#!/bin/bash
# deploy.sh — chạy trên server để build và serve blog

set -e

BLOG_DIR="$HOME/datpm-blog"
DIST_DIR="$BLOG_DIR/dist"

echo "▶ Pulling latest..."
cd "$BLOG_DIR"
git pull

echo "▶ Installing dependencies..."
npm install

echo "▶ Building..."
npm run build

echo "✓ Built to $DIST_DIR"
echo ""
echo "Caddy config cần có:"
echo ""
echo "datpm.com {"
echo "    root * $DIST_DIR"
echo "    try_files {path} {path}/index.html /index.html"
echo "    file_server"
echo "}"
