#!/usr/bin/env bash
# Установка панели управления шлюзом одной командой.
#
#   wget -qO- https://vpn-vendor.com/install | sudo bash
#
# Что делает сценарий (и ничего сверх этого):
#   1. проверяет, что система подходит;
#   2. подключает источник обновлений поставщика и его ключ проверки;
#   3. ставит пакет штатным менеджером — подпись проверяет сам менеджер.
#
# Пакет и все обновления проверяются подписью: подменить их, не имея нашего
# закрытого ключа, невозможно.
set -euo pipefail

REPO_URL="${VPN_PANEL_REPO:-https://apt.vpn-vendor.com}"
SUITE="${VPN_PANEL_SUITE:-resolute}"
KEYRING=/usr/share/keyrings/vpn-panel.asc
SOURCE=/etc/apt/sources.list.d/vpn-panel.sources

say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
fail() { printf '\nОшибка: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || fail "запустите с правами администратора: wget -qO- https://vpn-vendor.com/install | sudo bash"

say "Что будет сделано"
cat <<TXT
  1. Подключён источник обновлений: $REPO_URL
  2. Установлен ключ, которым проверяется подлинность пакетов
  3. Установлена панель управления шлюзом

Ничего другого сценарий не делает: настройки сети, файрвола и служб он не
трогает — этим займётся сама панель после установки, по вашей команде.
TXT

# Система: работаем только на поддерживаемой версии, иначе честный отказ.
. /etc/os-release 2>/dev/null || fail "не удалось определить систему"
if [ "${ID:-}" != "ubuntu" ]; then
    fail "панель рассчитана на Ubuntu; у вас ${PRETTY_NAME:-неизвестная система}"
fi
if [ "${VERSION_ID:-}" != "26.04" ]; then
    printf '\nВнимание: панель проверена на Ubuntu 26.04, у вас %s.\n' "${VERSION_ID:-?}"
    printf 'Установка продолжится, но работа не гарантируется.\n'
fi
[ "$(dpkg --print-architecture)" = "amd64" ] || fail "поддерживается только архитектура amd64"

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

Обновления будут приходить обычным «apt upgrade» и проверяться подписью.
TXT
