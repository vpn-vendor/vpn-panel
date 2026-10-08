#!/usr/bin/env bash
# Описание приложения с актуальным списком выпусков.
#
# Список берётся из changelog: руками он отстаёт, и магазин приложений
# показывает «Обновлено: неизвестно».
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="${1:-$ROOT/debian/assets/com.vpn_vendor.panel.metainfo.xml}"
KEEP="${METAINFO_RELEASES:-10}"

grep -q '<!--RELEASES-->' "$TEMPLATE" || {
    echo "в шаблоне нет метки <!--RELEASES-->: $TEMPLATE" >&2; exit 3; }

cd "$ROOT"
releases="  <releases>"
n=0
kept=0
while [ "$kept" -lt "$KEEP" ]; do
    ver="$(dpkg-parsechangelog -o "$n" -c 1 -S Version 2>/dev/null || true)"
    [ -n "$ver" ] || break
    # Открытая запись версии — ещё не выпуск.
    if [ "$(dpkg-parsechangelog -o "$n" -c 1 -S Distribution)" = "UNRELEASED" ]; then
        n=$((n + 1)); continue
    fi
    raw="$(dpkg-parsechangelog -o "$n" -c 1 -S Date)"
    day="$(date -u -d "$raw" +%Y-%m-%d)"
    releases="$releases
    <release version=\"$ver\" date=\"$day\"/>"
    n=$((n + 1)); kept=$((kept + 1))
done
releases="$releases
  </releases>"

# Подстановка многострочного текста: awk, а не sed — так не нужно
# экранировать содержимое и оно не может испортить XML.
awk -v rel="$releases" '{ if ($0 ~ /<!--RELEASES-->/) print rel; else print }' "$TEMPLATE"
