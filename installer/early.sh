#!/bin/sh
# Ранние шаги установки шлюза, до разметки.
# Образ Ubuntu должен быть того выпуска, под который собран носитель панели:
# иначе пакеты с носителя не подойдут системе.
# Ровно один внутренний диск: установка стирает его целиком, и второй диск с
# данными офиса не должен оказаться под ударом. Носитель установки (USB,
# привод) внутренним не считается.
# Временный ключ шифрования рождается здесь и вписывается в профиль, который
# установщик перечитывает после ранних шагов: в тексте профиля ключа нет.
set -eu
MEDIA="${VP_MEDIA:?}"
PROFILE=/autoinstall.yaml
KEY=/run/vp-temp-key
# Длина ключа — требование стойкости (64 знака из 62 — более 380 бит), не мощность.
KEY_CHARS=64

want="$(sed -n 's/^ubuntu=//p' "$MEDIA/vpn-panel/media.info")"
if [ -f /cdrom/.disk/info ] && ! grep -q "Ubuntu $want" /cdrom/.disk/info; then
    echo "vpn-panel: носитель панели собран для Ubuntu $want, а образ — «$(cat /cdrom/.disk/info)». Возьмите образ Ubuntu $want." >&2
    exit 1
fi

disks="$(lsblk -dnro NAME,TYPE,RM,TRAN | awk '$2=="disk" && $3=="0" && $4!="usb" && $1 !~ /^(zram|loop|sr)/ {print $1}')"
count="$(printf '%s\n' "$disks" | grep -c . || true)"
if [ "$count" -ne 1 ]; then
    echo "vpn-panel: внутренних дисков — $count ($(echo $disks)). Оставьте подключённым только диск, на который ставится шлюз: он будет стёрт целиком." >&2
    exit 1
fi

umask 077
tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$KEY_CHARS" > "$KEY"
python3 - "$PROFILE" "$KEY" <<'PYEOF'
import sys
import yaml

path, keyfile = sys.argv[1], sys.argv[2]
with open(keyfile) as f:
    key = f.read()
with open(path) as f:
    doc = yaml.safe_load(f)
doc.get("autoinstall", doc)["storage"]["layout"]["password"] = key
with open(path, "w") as f:
    yaml.safe_dump(doc, f)
PYEOF
echo "vpn-panel: диск $disks, временный ключ создан, носитель панели $(sed -n 's/^version=//p' "$MEDIA/vpn-panel/media.info")"
