#!/usr/bin/env bash
# Установка панели управления шлюзом одной командой.
#
#   wget -qO- https://vpn-vendor.github.io/vpn-panel/install.sh | sudo bash
#
# Что делает сценарий (и ничего сверх этого):
#   1. проверяет, что система подходит;
#   2. подключает источник обновлений поставщика и его ключ проверки;
#   3. ставит пакет штатным менеджером — подпись проверяет сам менеджер.
#
# Пакет и все обновления проверяются подписью: подменить их, не имея нашего
# закрытого ключа, невозможно.
set -euo pipefail

REPO_URL="${VPN_PANEL_REPO:-https://vpn-vendor.github.io/vpn-panel}"
KEYRING=/usr/share/keyrings/vpn-panel.asc
SOURCE=/etc/apt/sources.list.d/vpn-panel.sources

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
fail() { printf '\nОшибка: %s\n' "$*" >&2; exit 1; }
# Сценарий скачивают и wget, и curl: берём тот, что есть.
fetch() { if command -v wget >/dev/null 2>&1; then wget -qO- "$1"; else curl -fsSL "$1"; fi; }

[ "$(id -u)" = "0" ] || fail "запустите с правами администратора: wget -qO- https://vpn-vendor.github.io/vpn-panel/install.sh | sudo bash"

say "Что будет сделано"
cat <<TXT
  1. Подключён источник обновлений: $REPO_URL
  2. Установлен ключ, которым проверяется подлинность пакетов
  3. Установлена панель управления шлюзом

Ничего другого сценарий не делает: настройки сети, файрвола и служб он не
трогает — этим займётся сама панель после установки, по вашей команде.
TXT

# Система: ставим только на выпуски из окна поддержки, иначе честный отказ.
# Список берётся с той же площадки, что ключ и пакет: так он не расходится
# с репозиторием.
. /etc/os-release 2>/dev/null || fail "не удалось определить систему"
if [ "${ID:-}" != "ubuntu" ]; then
    fail "панель рассчитана на Ubuntu; у вас ${PRETTY_NAME:-неизвестная система}"
fi
[ "$(dpkg --print-architecture)" = "amd64" ] || fail "поддерживается только архитектура amd64"
WINDOW="$(fetch "$REPO_URL/os-window")" \
    || fail "не удалось скачать список поддерживаемых выпусков с $REPO_URL — проверьте интернет и повторите"
SUPPORTED="$(printf '%s\n' "$WINDOW" | awk '!/^#/ && NF == 2 {printf "%s%s", sep, $1; sep = ", "}')"
# Совпадение ищет сам awk и дочитывает список до конца: grep -q после awk
# под pipefail провалил бы конвейер на поддерживаемой системе.
if [ -z "${VPN_PANEL_SUITE:-}" ] &&
    ! printf '%s\n' "$WINDOW" | awk -v c="${VERSION_CODENAME:-}" '!/^#/ && NF == 2 && $2 == c {f = 1} END {exit !f}'; then
    fail "панель ставится на Ubuntu $SUPPORTED, а у вас ${PRETTY_NAME:-другая версия}. Обновите систему до одного из этих выпусков или поставьте шлюз с флешки"
fi
SUITE="${VPN_PANEL_SUITE:-$VERSION_CODENAME}"

say "Подключаю источник обновлений"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1 || true
apt-get install -y -qq ca-certificates wget >/dev/null

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
wget -qO "$tmp" "$REPO_URL/vpn-panel.asc" || fail "не удалось скачать ключ проверки с $REPO_URL"
grep -q 'BEGIN PGP PUBLIC KEY BLOCK' "$tmp" || fail "скачанный ключ повреждён — повторите позже"
install -D -m 0644 "$tmp" "$KEYRING"

cat > "$SOURCE" <<SRC
Types: deb
URIs: $REPO_URL
Suites: $SUITE
Components: main
Architectures: amd64
Signed-By: $KEYRING
SRC

say "Устанавливаю панель"
apt-get update -qq
apt-get install -y vpn-panel

say "Готово"
cat <<TXT
Панель установлена и уже работает. Дальше:

  1. Выполните: sudo vpn-panel-code
     Команда напечатает код входа и адрес, по которому панель открыта в
     локальной сети.
  2. Откройте этот адрес в браузере с любого компьютера офиса и введите код.

Если панель в браузере не открывается, шлюзом можно управлять с консоли:
  sudo vpn-panel

Обновления будут приходить обычным «apt upgrade» и проверяться подписью.
TXT
