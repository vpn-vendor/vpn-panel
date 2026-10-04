#!/bin/sh
# Шаги установки шлюза после разметки: пакет панели и его зависимости из
# репозитория на носителе (сеть при установке не нужна), имя шлюза,
# временный ключ в initramfs, шифр по железу и TRIM. Журнал шагов остаётся в
# журналах установщика установленной системы.
set -eu
HERE="${VP_MEDIA:?}/vpn-panel"
LOG=/target/var/log/installer/vpn-panel-install.log
KEY=/run/vp-temp-key
PLACEHOLDER=VP-TEMP-KEY-PLACEHOLDER
HOSTNAME=office-gateway
mkdir -p "$(dirname "$LOG")"
out() { echo "vpn-panel: $*" | tee -a "$LOG"; }

# Источник системы на время установки выключен: всё — из носителя.
# Носитель — локальные файлы, его подлинность несёт контрольная сумма самого
# носителя. Подпись и даты здесь только мешали бы: истёкший ключ или сбитые
# часы сервера остановили бы установку без сети.
REPO=/var/cache/vpn-panel-media
LIST=/etc/apt/vpn-panel-media.list
mkdir -p "/target$REPO"
cp -a "$HERE/repo/." "/target$REPO/"
echo "deb [trusted=yes check-date=no check-valid-until=no] file:$REPO ./" > "/target$LIST"
O="-o Dir::Etc::SourceList=$LIST -o Dir::Etc::SourceParts=/nonexistent"
if ! curtin in-target -- apt-get $O update >> "$LOG" 2>&1 || \
   ! curtin in-target -- env DEBIAN_FRONTEND=noninteractive apt-get $O install -y --no-install-recommends vpn-panel >> "$LOG" 2>&1; then
    out "VP-OFFLINE: FAIL — пакеты с носителя не установились, подробности выше в журнале"
    exit 1
fi
rm -rf "/target$REPO" "/target$LIST"
out "VP-OFFLINE: OK $(curtin in-target -- dpkg-query -W -f='${Version}' vpn-panel)"

echo "$HOSTNAME" > /target/etc/hostname
if grep -q '^127\.0\.1\.1[[:space:]]' /target/etc/hosts; then
    sed -i "s/^127\.0\.1\.1[[:space:]].*/127.0.1.1\t$HOSTNAME/" /target/etc/hosts
else
    printf '127.0.1.1\t%s\n' "$HOSTNAME" >> /target/etc/hosts
fi
out "имя шлюза: $HOSTNAME"

VP_KEY_FILE="$KEY" VP_PLACEHOLDER="$PLACEHOLDER" VP_LOG="$LOG" sh "$HERE/firstboot-key.sh"
VP_KEY_FILE="$KEY" VP_LOG="$LOG" sh "$HERE/disk-cipher.sh"
