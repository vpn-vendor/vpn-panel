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
# Наш том — тот, который открывает временный ключ: рядом может стоять чужой
# шифрованный раздел другой системы.
D=""
for cand in $(lsblk -pnro NAME,FSTYPE | awk '$2=="crypto_LUKS"{print $1}'); do
    if cryptsetup open --test-passphrase --key-file "$KEY" "$cand" 2>/dev/null; then
        D="$cand"
        break
    fi
done
[ -n "$D" ] || { out "VP-FIRSTBOOT: FAIL temporary key does not open any LUKS volume"; exit 1; }
if printf %s "$PLACEHOLDER" | cryptsetup open --test-passphrase --key-file - "$D" 2>/dev/null; then
    out "VP-FIRSTBOOT: FAIL placeholder opens the disk"
    exit 1
fi
echo "$D" > /run/vp-luks-device
install -d -m 0700 /target/etc/cryptsetup-keys.d
install -m 0400 "$KEY" /target/etc/cryptsetup-keys.d/system.key
printf 'install_items+=" /etc/cryptsetup-keys.d/system.key "\n' \
    > /target/etc/dracut.conf.d/90-vpn-panel-first-boot-key.conf
# Первое поле — имя тома, четвёртое — параметры.
awk 'BEGIN{OFS=" "} /^[^#]/ && NF>=3 {$1="system"; if (NF<4) $4="luks"; if ($4 !~ /tries=/) $4=$4",tries=0"} {print}' \
    /target/etc/crypttab > /target/etc/crypttab.new
mv /target/etc/crypttab.new /target/etc/crypttab
out "VP-FIRSTBOOT: OK crypttab=$(grep -v '^#' /target/etc/crypttab | tr -s ' ' | cut -d' ' -f1,3,4)"
