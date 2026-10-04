#!/usr/bin/env bash
# Сборка носителя установки шлюза из пакета панели.
#
# Комплект: профиль установки, шаги и репозиторий с пакетом панели и всем,
# что он тянет за собой. Состав репозитория решает apt на пустой системе того
# же выпуска Ubuntu (полное замыкание зависимостей): носитель одинаково
# ставится на образ Ubuntu старше и моложе себя. Списка пакетов в тексте нет.
#
#   build-media.sh --deb <пакет> --out <каталог>
#                  [--kit <архив.zip>] [--cidata <образ.iso>]
#                  [--iso <официальный ISO Ubuntu> --iso-out <образ.iso>] [--unattended]
#                  [--profile <файл>] [--extra <каталог>]
#
#   --kit         комплект файлов для флешки (публикуется)
#   --cidata      тот же комплект образом с меткой cidata (вторая флешка, виртуальная машина)
#   --iso         образ Ubuntu с комплектом и своим меню загрузки (опытный пользователь собирает сам)
#   --unattended  пункт меню без подтверждения стирания — для массовой установки
#   --extra       дополнительные файлы, которые кладутся на носитель рядом с комплектом
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# Выпуск Ubuntu, под который собран пакет; его же требует ранний шаг установки.
UBUNTU=26.04
DEB="" OUT="" KIT="" CIDATA="" ISO="" ISO_OUT="" EXTRA="" UNATTENDED=0 PROFILE="$HERE/user-data"
while [ $# -gt 0 ]; do
    case "$1" in
        --deb) DEB="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --kit) KIT="$2"; shift 2 ;;
        --cidata) CIDATA="$2"; shift 2 ;;
        --iso) ISO="$2"; shift 2 ;;
        --iso-out) ISO_OUT="$2"; shift 2 ;;
        --unattended) UNATTENDED=1; shift ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --extra) EXTRA="$2"; shift 2 ;;
        *) echo "неизвестный аргумент: $1" >&2; exit 2 ;;
    esac
done
[ -n "$DEB" ] && [ -n "$OUT" ] || { echo "нужны --deb и --out" >&2; exit 2; }
[ -f "$DEB" ] || { echo "$DEB: нет такого пакета" >&2; exit 2; }
[ -z "$ISO" ] || [ -n "$ISO_OUT" ] || { echo "с --iso нужен --iso-out" >&2; exit 2; }
[ -z "$ISO" ] || [ -f "$ISO" ] || { echo "$ISO: нет такого образа" >&2; exit 2; }
command -v docker > /dev/null || { echo "нужен docker: состав репозитория решает apt в чистой системе" >&2; exit 2; }
[ -z "$CIDATA$ISO" ] || command -v xorriso > /dev/null || { echo "нужен xorriso" >&2; exit 2; }
[ -z "$KIT" ] || command -v zip > /dev/null || { echo "нужен zip" >&2; exit 2; }

# Заглушка ключа одна в профиле и в шагах: иначе проверка «заглушка не
# открывает диск» проверяла бы не ту строку.
in_profile="$(sed -n 's/^[[:space:]]*password:[[:space:]]*//p' "$PROFILE" | head -n 1)"
in_steps="$(sed -n 's/^PLACEHOLDER=//p' "$HERE/late.sh")"
[ -n "$in_profile" ] && [ "$in_profile" = "$in_steps" ] || { echo "заглушка ключа в профиле и в шагах различается" >&2; exit 1; }

abspath() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$PWD" "$1" ;; esac; }
DEB="$(abspath "$DEB")"
# Язык живой системы и окна подтверждения — тот же, что в профиле.
LOCALE="$(sed -n 's/^[[:space:]]*locale:[[:space:]]*//p' "$PROFILE" | head -n 1)"
[ -n "$LOCALE" ] || { echo "в профиле нет locale" >&2; exit 1; }
menu() { # $1 — файл, $2 — параметры ядра, $3 — вставка loopback
    sed "s|@AUTOINSTALL@|$2|g; s|@ISO_SCAN@|$3|g; s|@LOCALE@|$LOCALE|g" "$HERE/grub.cfg" | tr -s ' ' > "$1"
}
[ -z "$KIT" ] || KIT="$(abspath "$KIT")"
[ -z "$CIDATA" ] || CIDATA="$(abspath "$CIDATA")"
[ -z "$ISO" ] || ISO="$(abspath "$ISO")"
[ -z "$ISO_OUT" ] || ISO_OUT="$(abspath "$ISO_OUT")"
[ -z "$EXTRA" ] || EXTRA="$(abspath "$EXTRA")"
[ -z "$PROFILE" ] || PROFILE="$(abspath "$PROFILE")"
VERSION="$(dpkg-deb -f "$DEB" Version)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
REPO="$OUT/repo"
KITDIR="$OUT/kit"
rm -rf "$REPO" "$KITDIR"
mkdir -p "$REPO"

echo "== репозиторий: замыкание зависимостей решает apt (Ubuntu $UBUNTU)"
docker run --rm -v "$DEB:/vpn-panel.deb:ro" -v "$REPO:/repo" -e OWNER="$(id -u):$(id -g)" \
    "ubuntu:$UBUNTU" bash -c '
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
# Только основные карманы выпуска: из backports пакеты не попадают на носитель.
sed -i "s/ [a-z]*-backports//" /etc/apt/sources.list.d/ubuntu.sources
apt-get -qq update
apt-get -qq install -y --no-install-recommends dpkg-dev apt-utils > /dev/null
: > /tmp/nothing-installed
mkdir -p /tmp/arch/partial /repo/pool
# С точки зрения пустой системы: в комплект попадает всё, что нужно пакету,
# включая библиотеки, которые на образе Ubuntu могут оказаться старше.
# Архив обновляется прямо во время сборки: индекс уже новый, а файл ещё нет
# (или наоборот). Тогда перечитываем индекс и качаем снова — несколько раз.
for attempt in 1 2 3; do
    apt-get -o Dir::State::status=/tmp/nothing-installed -o Dir::Cache::archives=/tmp/arch \
        -y --no-install-recommends --download-only install /vpn-panel.deb > /tmp/apt.log 2>&1 && break
    [ "$attempt" = 3 ] && { cat /tmp/apt.log; exit 1; }
    echo "   загрузка не удалась (попытка $attempt), перечитываю индекс архива"
    sleep 20
    apt-get -qq update
done
cp /tmp/arch/*.deb /repo/pool/
cp /vpn-panel.deb "/repo/pool/$(basename "$(dpkg-deb -W --showformat="\${Package}_\${Version}_\${Architecture}.deb" /vpn-panel.deb)")"
cd /repo
dpkg-scanpackages --multiversion pool /dev/null > Packages 2> /dev/null
gzip -9kf Packages
apt-ftparchive -o APT::FTPArchive::Release::Origin="VPN Panel" \
    -o APT::FTPArchive::Release::Label="VPN Panel media" \
    -o APT::FTPArchive::Release::Description="Носитель установки шлюза" release . > /tmp/Release
mv /tmp/Release Release
# Страж замкнутости: пустая система и только этот репозиторий — apt обязан
# собрать установку панели целиком, иначе на шлюзе без сети её не собрать.
echo "deb [trusted=yes check-date=no check-valid-until=no] file:/repo ./" > /tmp/media.list
M="-o Dir::State::status=/tmp/nothing-installed -o Dir::Etc::SourceList=/tmp/media.list -o Dir::Etc::SourceParts=/nonexistent -o Dir::State::lists=/tmp/lists"
mkdir -p /tmp/lists/partial
apt-get $M -qq update
apt-get $M -s --no-install-recommends install vpn-panel > /tmp/sim.log 2>&1 \
    || { echo "репозиторий носителя не замкнут:"; cat /tmp/sim.log; exit 1; }
echo "   пакетов в репозитории: $(ls pool | wc -l); решатель на пустой системе поставил бы: $(grep -c "^Inst " /tmp/sim.log)"
chown -R "$OWNER" /repo
'

echo "== комплект"
mkdir -p "$KITDIR/vpn-panel"
install -m 0755 "$HERE/early.sh" "$HERE/late.sh" "$HERE/firstboot-key.sh" "$HERE/disk-cipher.sh" "$KITDIR/vpn-panel/"
cp -a "$REPO" "$KITDIR/vpn-panel/repo"
printf 'ubuntu=%s\nversion=%s\nbuilt=%s\n' "$UBUNTU" "$VERSION" "$(date -u +%F)" > "$KITDIR/vpn-panel/media.info"
cp "$PROFILE" "$KITDIR/user-data"
cp "$PROFILE" "$KITDIR/autoinstall.yaml"
printf 'instance-id: vpn-panel-%s\n' "$(date -u +%Y%m%d%H%M%S)" > "$KITDIR/meta-data"
sed "s/@VERSION@/$VERSION/g; s/@UBUNTU@/$UBUNTU/g" "$HERE/readme-kit.txt" > "$KITDIR/ПРОЧТИ-МЕНЯ.txt"
# Меню для записываемой флешки: скопированное в корень с заменой, оно даёт тот же
# русский экран и то же подтверждение стирания, что и собранный образ.
mkdir -p "$KITDIR/boot/grub"
menu "$KITDIR/boot/grub/grub.cfg" "" ""
menu "$KITDIR/boot/grub/loopback.cfg" "" 'iso-scan/filename=${iso_path}'
[ -z "$EXTRA" ] || cp -a "$EXTRA/." "$KITDIR/"

if [ -n "$KIT" ]; then
    rm -f "$KIT"
    ( cd "$KITDIR" && zip -q -r -X "$KIT" . )
    echo "комплект: $KIT ($(du -h "$KIT" | cut -f1))"
fi
if [ -n "$CIDATA" ]; then
    xorriso -as mkisofs -quiet -o "$CIDATA" -volid cidata -joliet -rock "$KITDIR"
    echo "образ cidata: $CIDATA ($(du -h "$CIDATA" | cut -f1))"
fi
if [ -n "$ISO" ]; then
    STAGE="$(mktemp -d)"
    trap 'rm -rf "$STAGE"' EXIT
    xorriso -osirrox on -indev "$ISO" -extract /md5sum.txt "$STAGE/md5sum.orig" \
        -extract /.disk/info "$STAGE/disk-info" > /dev/null 2>&1
    grep -q "Ubuntu $UBUNTU" "$STAGE/disk-info" \
        || { echo "$ISO: это не образ Ubuntu $UBUNTU («$(cat "$STAGE/disk-info")»)" >&2; exit 1; }
    ROOT="$STAGE/root"
    mkdir -p "$ROOT/boot/grub"
    cp -a "$KITDIR/vpn-panel" "$ROOT/vpn-panel"
    cp "$KITDIR/autoinstall.yaml" "$KITDIR/ПРОЧТИ-МЕНЯ.txt" "$ROOT/"
    # На образ идёт то же, что в комплекте, кроме профиля cloud-init и меню: меню здесь своё.
    [ -z "$EXTRA" ] || cp -a "$EXTRA/." "$ROOT/"
    AUTO=""
    [ "$UNATTENDED" = 1 ] && AUTO=autoinstall
    menu "$ROOT/boot/grub/grub.cfg" "$AUTO" ""
    menu "$ROOT/boot/grub/loopback.cfg" "$AUTO" 'iso-scan/filename=${iso_path}'
    # Список контрольных сумм образа: заменённые файлы — новыми суммами,
    # добавленные — дописаны. Иначе штатная проверка носителя красная.
    grep -vE ' \./boot/grub/(grub|loopback)\.cfg$' "$STAGE/md5sum.orig" > "$ROOT/md5sum.txt"
    ( cd "$ROOT" && find . -type f ! -name md5sum.txt -print0 | LC_ALL=C sort -z | xargs -0 md5sum ) >> "$ROOT/md5sum.txt"
    # Загрузочная схема (BIOS, UEFI, гибридная разметка) повторяется с оригинала.
    rm -f "$ISO_OUT"
    xorriso -indev "$ISO" -outdev "$ISO_OUT" -boot_image any replay -joliet on \
        -map "$ROOT" / > "$STAGE/xorriso.log" 2>&1 \
        || { cat "$STAGE/xorriso.log" >&2; exit 1; }
    echo "образ: $ISO_OUT ($(du -h "$ISO_OUT" | cut -f1), меню $([ "$UNATTENDED" = 1 ] && echo 'без подтверждения' || echo 'с подтверждением стирания'))"
fi
echo "носитель панели $VERSION для Ubuntu $UBUNTU: $KITDIR"
