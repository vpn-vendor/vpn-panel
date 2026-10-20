#!/bin/sh
# Ранние шаги установки шлюза, до разметки.
# Образ Ubuntu должен быть того выпуска, под который собран носитель панели:
# иначе пакеты с носителя не подойдут системе.
# Три режима, выбираются пунктом меню (параметр ядра):
#  - стереть весь диск: ровно один внутренний диск, иначе второй диск с
#    данными офиса оказался бы под ударом;
#  - рядом с другой системой (vp.beside=1): шлюз ставится в свободное место
#    диска, чужие разделы не трогаются; разметку пишет этот шаг, а не
#    установщик;
#  - переустановить (vp.reinstall=1): прежний шлюз, поставленный рядом с
#    другой системой, стирается и ставится заново в свои же разделы; границы
#    разделов не меняются, чужие разделы не трогаются.
# Носитель установки (USB, привод) внутренним не считается.
# Временный ключ шифрования рождается здесь и вписывается в профиль, который
# установщик перечитывает после ранних шагов: в тексте профиля ключа нет.
# Остановка — до единой записи на диск; текст причины берётся из
# reasons.tsv по имени и виден человеку по кнопке «Показать журнал».
set -eu
MEDIA="${VP_MEDIA:?}"
PROFILE=/autoinstall.yaml
KEY=/run/vp-temp-key
# Генератор разметки называет причину остановки сюда: текст собирает оболочка.
STOP_ID=/run/vp-stop-id
VP_REASONS="$MEDIA/vpn-panel/reasons.tsv"
. "$MEDIA/vpn-panel/reasons.sh"
# Длина ключа — требование стойкости (64 знака из 62 — более 380 бит), не мощность.
KEY_CHARS=64
# Сколько свободного места нужно шлюзу рядом с другой системой: система,
# обновления и журналы панели с запасом. Класс: ёмкость диска, не мощность.
MIN_FREE_GIB=40
# Раздел /boot вне шифрования: несколько ядер с запасом.
BOOT_MIB=2048
# Свободное место в загрузочном разделе прошивки под наш загрузчик.
ESP_FREE_MIB=32

# Генератор разметки остановился: имя причины, подробность и подстановки — в
# файле через разделитель \037 (пустые поля не схлопываются). Нет файла —
# генератор упал сам.
broke() {
    if [ -s "$STOP_ID" ]; then
        IFS="$(printf '\037')" read -r id detail a1 a2 < "$STOP_ID" || true
        vp_stop "$id" "$detail" "$a1" "$a2"
    fi
    vp_stop layout-failed "генератор разметки упал без своей причины"
}

want="$(sed -n 's/^ubuntu=//p' "$MEDIA/vpn-panel/media.info")"
if [ -f /cdrom/.disk/info ] && ! grep -q "Ubuntu $want" /cdrom/.disk/info; then
    vp_stop wrong-image "$(cat /cdrom/.disk/info)" "$want"
fi

mode=erase
if grep -qw 'vp\.beside=1' /proc/cmdline; then
    mode=beside
fi
if grep -qw 'vp\.reinstall=1' /proc/cmdline; then
    mode=reinstall
fi
echo "$mode" > /run/vp-install-mode

disks="$(lsblk -dnro NAME,TYPE,RM,TRAN | awk '$2=="disk" && $3=="0" && $4!="usb" && $1 !~ /^(zram|loop|sr)/ {print $1}')"
count="$(printf '%s\n' "$disks" | grep -c . || true)"
if [ "$mode" = erase ] && [ "$count" -ne 1 ]; then
    vp_stop disks-count "$(echo $disks)" "$count"
fi
if [ "$mode" != erase ] && [ ! -d /sys/firmware/efi ]; then
    vp_stop no-uefi "режим $mode без /sys/firmware/efi"
fi

umask 077
tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$KEY_CHARS" > "$KEY"
VP_MODE="$mode" VP_DISKS="$disks" VP_MIN_FREE_GIB="$MIN_FREE_GIB" VP_BOOT_MIB="$BOOT_MIB" VP_ESP_FREE_MIB="$ESP_FREE_MIB" \
VP_STOP_ID="$STOP_ID" python3 - "$PROFILE" "$KEY" <<'PYEOF' || broke
import json
import os
import re
import subprocess
import sys
import yaml

path, keyfile = sys.argv[1], sys.argv[2]
with open(keyfile) as f:
    key = f.read()
with open(path) as f:
    doc = yaml.safe_load(f)
ai = doc.get("autoinstall", doc)

MIB = 2**20
GIB = 2**30
ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
BOOT_NAME, LUKS_NAME = "vpn-panel-boot", "vpn-panel"
mode = os.environ["VP_MODE"]


def fail(reason, detail="", *args):
    """Остановка: имя причины из reasons.tsv; текст человеку собирает оболочка."""
    with open(os.environ["VP_STOP_ID"], "w") as f:
        f.write("\037".join([reason, detail] + [str(a) for a in args]) + "\n")
    sys.exit(1)


def table(dev):
    out = subprocess.run(["sfdisk", "-J", dev], capture_output=True, text=True)
    if out.returncode != 0:
        return None
    return json.loads(out.stdout)["partitiontable"]


def gaps(pt):
    """Свободные участки диска в байтах, выровненные по мегабайту."""
    sec = pt.get("sectorsize", 512)
    parts = sorted(pt.get("partitions", []), key=lambda p: p["start"])
    out, cursor = [], pt["firstlba"] * sec
    for p in parts:
        start = p["start"] * sec
        if start - cursor >= MIB:
            out.append((cursor, start))
        cursor = max(cursor, (p["start"] + p["size"]) * sec)
    end = (pt["lastlba"] + 1) * sec
    if end - cursor >= MIB:
        out.append((cursor, end))
    aligned = []
    for a, b in out:
        a = (a + MIB - 1) // MIB * MIB
        b = b // MIB * MIB
        if b > a:
            aligned.append((a, b))
    return aligned


def number(p):
    """Номер раздела — из имени узла: в JSON у sfdisk поля номера нет."""
    return int(re.search(r"(\d+)$", p["node"]).group(1))


def fstypes(dev):
    out = subprocess.run(["lsblk", "-nro", "NAME,FSTYPE", dev], capture_output=True, text=True).stdout
    return {ln.split()[0]: (ln.split() + [""])[1] for ln in out.splitlines() if ln.strip()}


def esp_free_mib(node):
    mnt = "/run/vp-esp"
    os.makedirs(mnt, exist_ok=True)
    if subprocess.run(["mount", "-o", "ro", node, mnt], capture_output=True).returncode != 0:
        return -1
    try:
        st = os.statvfs(mnt)
        return st.f_bavail * st.f_frsize // MIB
    finally:
        subprocess.run(["umount", mnt], capture_output=True)


def disk_paths():
    return ["/dev/" + name for name in os.environ["VP_DISKS"].split()]


def gpt_disks():
    for dev in disk_paths():
        pt = table(dev)
        if pt and pt.get("label") == "gpt":
            yield dev, pt


def single_esp(pt):
    esp = [p for p in pt["partitions"] if p.get("type", "").lower() == ESP]
    if len(esp) != 1:
        fail("no-esp", "разделов UEFI: %d" % len(esp))
    return esp[0]


def no_bitlocker(dev):
    if any(v.lower() == "bitlocker" for v in fstypes(dev).values()):
        fail("bitlocker", dev)


def keep_entries(pt, esp):
    """Существующие разделы как есть: тип, смещение, размер; загрузчик — в раздел UEFI."""
    sec = pt.get("sectorsize", 512)
    out = []
    for p in sorted(pt["partitions"], key=number):
        entry = {"type": "partition", "id": "keep%d" % number(p), "device": "disk0", "number": number(p),
                 "offset": p["start"] * sec, "size": p["size"] * sec, "preserve": True,
                 "partition_type": p["type"]}
        if p is esp:
            entry["flag"] = "boot"
            entry["grub_device"] = True
        out.append(entry)
    return out


def gateway_tail(esp, boot_id, luks_id):
    """Наша часть разметки: /boot, том LUKS с временным ключом, LVM и корень."""
    return [
        {"type": "format", "id": "fmt-esp", "volume": "keep%d" % number(esp), "fstype": "fat32", "preserve": True},
        {"type": "mount", "id": "mnt-esp", "device": "fmt-esp", "path": "/boot/efi"},
        {"type": "format", "id": "fmt-boot", "volume": boot_id, "fstype": "ext4"},
        {"type": "mount", "id": "mnt-boot", "device": "fmt-boot", "path": "/boot"},
        {"type": "dm_crypt", "id": "crypt", "volume": luks_id, "key": key, "dm_name": "system"},
        {"type": "lvm_volgroup", "id": "vg", "name": "ubuntu-vg", "devices": ["crypt"]},
        {"type": "lvm_partition", "id": "root", "volgroup": "vg", "name": "ubuntu-lv"},
        {"type": "format", "id": "fmt-root", "volume": "root", "fstype": "ext4"},
        {"type": "mount", "id": "mnt-root", "device": "fmt-root", "path": "/"},
    ]


def write(dev, config, boot_no, luks_no, note):
    ai["storage"] = {"version": 2, "config": config}
    with open(path, "w") as f:
        yaml.safe_dump(doc, f)
    with open("/run/vp-install-disk", "w") as f:
        f.write("%s %d %d\n" % (dev, boot_no, luks_no))
    print("vpn-panel: " + note)


if mode == "erase":
    ai["storage"]["layout"]["password"] = key
    with open(path, "w") as f:
        yaml.safe_dump(doc, f)
    sys.exit(0)

if mode == "reinstall":
    found = []
    for dev, pt in gpt_disks():
        boots = [p for p in pt["partitions"] if p.get("name") == BOOT_NAME]
        lukss = [p for p in pt["partitions"] if p.get("name") == LUKS_NAME]
        if boots or lukss:
            found.append((dev, pt, boots, lukss))
    if not found:
        fail("no-old-gateway")
    if len(found) > 1:
        fail("gateway-several-disks", ", ".join(d for d, _, _, _ in found))
    dev, pt, boots, lukss = found[0]
    if len(boots) != 1 or len(lukss) != 1:
        fail("gateway-parts-mismatch", "%s: boot=%d, luks=%d" % (dev, len(boots), len(lukss)))
    boot, luks = boots[0], lukss[0]
    kind = subprocess.run(["blkid", "-o", "value", "-s", "TYPE", luks["node"]], capture_output=True, text=True).stdout.strip()
    if kind != "crypto_LUKS":
        fail("gateway-not-luks", "%s: %s" % (luks["node"], kind or "без подписи"))
    esp = single_esp(pt)
    no_bitlocker(dev)
    boot_no, luks_no = number(boot), number(luks)
    config = [{"type": "disk", "id": "disk0", "path": dev, "ptable": "gpt", "preserve": True}]
    config += keep_entries(pt, esp)
    # Прежний заголовок LUKS стирается до нового шифрования: иначе cryptsetup
    # спросил бы подтверждение, а спросить некого.
    next(e for e in config if e["id"] == "keep%d" % luks_no)["wipe"] = "superblock"
    config += gateway_tail(esp, "keep%d" % boot_no, "keep%d" % luks_no)
    sec = pt.get("sectorsize", 512)
    write(dev, config, boot_no, luks_no,
          "переустановка — диск %s, разделы %d и %d (%d ГБ) стираются и ставятся заново; остальные разделы не трогаются"
          % (dev, boot_no, luks_no, luks["size"] * sec // GIB))
    sys.exit(0)

min_free = int(os.environ["VP_MIN_FREE_GIB"]) * GIB
boot_size = int(os.environ["VP_BOOT_MIB"]) * MIB
esp_need = int(os.environ["VP_ESP_FREE_MIB"])
found = []
for dev, pt in gpt_disks():
    best = max(gaps(pt), key=lambda g: g[1] - g[0], default=None)
    if best and best[1] - best[0] >= min_free:
        found.append((dev, pt, best))
if not found:
    if any(p.get("name") == LUKS_NAME for _, pt in gpt_disks() for p in pt["partitions"]):
        fail("gateway-present")
    # Система в режиме BIOS на разметке MBR: сжимать её раздел бесполезно —
    # без GPT шлюз рядом не встанет, совет «сожмите раздел» был бы неверным.
    if not any(True for _ in gpt_disks()) and any(table(d) and table(d).get("label") == "dos"
                                                   and table(d).get("partitions") for d in disk_paths()):
        fail("mbr", " ".join(disk_paths()))
    fail("no-free-space", "", min_free // GIB)
if len(found) > 1:
    fail("free-several-disks", ", ".join(d for d, _, _ in found))
dev, pt, (gap_start, gap_end) = found[0]
no_bitlocker(dev)
esp = single_esp(pt)
free = esp_free_mib(esp["node"])
if free < esp_need:
    fail("esp-small", esp["node"], "размер не прочитан" if free < 0 else "%d МБ" % free, esp_need)

numbers = [number(p) for p in pt["partitions"]]
boot_no, luks_no = max(numbers) + 1, max(numbers) + 2
config = [{"type": "disk", "id": "disk0", "path": dev, "ptable": "gpt", "preserve": True}]
config += keep_entries(pt, esp)
config += [
    {"type": "partition", "id": "boot", "device": "disk0", "number": boot_no, "offset": gap_start, "size": boot_size,
     "partition_name": BOOT_NAME},
    {"type": "partition", "id": "luks", "device": "disk0", "number": luks_no, "offset": gap_start + boot_size,
     "size": gap_end - gap_start - boot_size, "partition_name": LUKS_NAME},
]
config += gateway_tail(esp, "boot", "luks")
write(dev, config, boot_no, luks_no,
      "рядом с другой системой — диск %s, свободно %d ГБ с %d МБ, разделы %d и %d; остальные разделы не трогаются"
      % (dev, (gap_end - gap_start) // GIB, gap_start // MIB, boot_no, luks_no))
PYEOF
echo "vpn-panel: режим $mode, диск $(cat /run/vp-install-disk 2>/dev/null || echo "$disks"), временный ключ создан, носитель панели $(sed -n 's/^version=//p' "$MEDIA/vpn-panel/media.info")"
