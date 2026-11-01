#!/usr/bin/env bash
# Amos · CF 优选 一键安装：安装依赖 → 编译 → 桌面图标 → 加入开机自启 → 启动并打开页面
# Debian/Ubuntu/Termux/macOS：
#   curl -fsSL https://raw.githubusercontent.com/<你的用户名>/cf-ip-optimizer/main/install.sh | CFIP_REPO=https://github.com/<你的用户名>/cf-ip-optimizer.git bash
# 可用环境变量：CFIP_REPO（仓库地址）CFIP_DIR（安装目录，默认 ~/cfip）CFIP_PORT（端口，默认 18443）
set -euo pipefail
REPO="${CFIP_REPO:-https://github.com/YOUR_NAME/cf-ip-optimizer.git}"
DIR="${CFIP_DIR:-$HOME/cfip}"; PORT="${CFIP_PORT:-18443}"; LIBS="-lpthread"

if command -v apt-get >/dev/null; then sudo apt-get update -y && sudo apt-get install -y build-essential pkg-config libcurl4-openssl-dev git
elif [ -n "${TERMUX_VERSION:-}" ]; then pkg install -y clang pkg-config libcurl git; LIBS=""
elif command -v brew >/dev/null; then brew install pkg-config curl git; fi

if [ -f cf_ip_test_tls.c ]; then DIR="$PWD"; else git clone --depth 1 "$REPO" "$DIR"; fi
cd "$DIR"
cc -O2 -Wall -o cfip cf_ip_test_tls.c $(pkg-config --cflags --libs libcurl 2>/dev/null || echo -lcurl) $LIBS

# 桌面图标（使用与主页 tab 相同的 logo）
if [ "$(uname)" = Linux ] && [ -z "${TERMUX_VERSION:-}" ]; then
  mkdir -p "$HOME/.local/share/applications" "$HOME/.local/share/icons/hicolor/256x256/apps"
  cp assets/icons/cfip-256.png "$HOME/.local/share/icons/hicolor/256x256/apps/cfip.png"
  sed "s|^Exec=.*|Exec=$DIR/cfip|" assets/cfip.desktop > "$HOME/.local/share/applications/cfip.desktop"
fi

./cfip --autostart "$PORT"
if command -v systemctl >/dev/null && systemctl --user start cfip 2>/dev/null; then :; else nohup ./cfip --no-browser "$PORT" >/dev/null 2>&1 & fi
URL="http://127.0.0.1:$PORT/"
echo "已启动：$URL   （数据目录：$DIR/data）"
if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v xdg-open >/dev/null; then xdg-open "$URL" >/dev/null 2>&1 || true; fi
