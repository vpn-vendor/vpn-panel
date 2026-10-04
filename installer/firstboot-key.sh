#!/bin/sh
# Временный ключ установки — в initramfs: первая загрузка открывает диск сама,
# до шага, где человек задаёт пароль. Том называется system, попыток ввода
# не ограничено. Установка останавливается, если диск открывает заглушка из
# профиля: значит, ключ в профиль не вписан.
set -eu
KEY="${VP_KEY_FILE:?}"
PLACEHOLDER="${VP_PLACEHOLDER:?}"
LOG="${VP_LOG:?}"
out() { echo "vpn-panel: $*" | tee -a "$LOG"; }
D="$(lsblk -pnro NAME,FSTYPE | awk '$2=="crypto_LUKS"{print $1; exit}')"
[ -n "$D" ] || { out "VP-FIRSTBOOT: FAIL no LUKS volume"; exit 1; }
if printf %s "$PLACEHOLDER" | cryptsetup open --test-passphrase --key-file - "$D" 2>/dev/null; then
    out "VP-FIRSTBOOT: FAIL placeholder opens the disk"
    exit 1
fi
printf %s "$(cat "$KEY")" | cryptsetup open --test-passphrase --key-file - "$D" \
    || { out "VP-FIRSTBOOT: FAIL temporary key does not open the disk"; exit 1; }
install -d -m 0700 /target/etc/cryptsetup-keys.d
install -m 0400 "$KEY" /target/etc/cryptsetup-keys.d/system.key
printf 'install_items+=" /etc/cryptsetup-keys.d/system.key "\n' \
    > /target/etc/dracut.conf.d/90-vpn-panel-first-boot-key.conf
# Первое поле — имя тома, четвёртое — параметры.
awk 'BEGIN{OFS=" "} /^[^#]/ && NF>=3 {$1="system"; if (NF<4) $4="luks"; if ($4 !~ /tries=/) $4=$4",tries=0"} {print}' \
    /target/etc/crypttab > /target/etc/crypttab.new
mv /target/etc/crypttab.new /target/etc/crypttab
out "VP-FIRSTBOOT: OK crypttab=$(grep -v '^#' /target/etc/crypttab | tr -s ' ' | cut -d' ' -f1,3,4)"
