#!/bin/sh
# Шаги установки шлюза после разметки: пакет панели и его зависимости из
# репозитория на носителе (сеть при установке не нужна), имя шлюза,
# временный ключ в initramfs, шифр по железу и TRIM; в конце — самопроверка
# образов загрузки. Журнал шагов остаётся в журналах установщика
# установленной системы. Остановка — с причиной из reasons.tsv.
set -eu
HERE="${VP_MEDIA:?}/vpn-panel"
VP_REASONS="$HERE/reasons.tsv"
. "$HERE/reasons.sh"
LOG=/target/var/log/installer/vpn-panel-install.log
KEY=/run/vp-temp-key
PLACEHOLDER=VP-TEMP-KEY-PLACEHOLDER
HOSTNAME=office-gateway
mkdir -p "$(dirname "$LOG")"
out() { echo "vpn-panel: $*" | tee -a "$LOG"; }

# Шаг упал не своей остановкой (например, внутри firstboot-key.sh): человеку —
# общая причина, подробность — в журнале выше.
on_exit() {
    rc=$?
    trap - EXIT
    [ "$rc" -eq 0 ] || [ -s "$VP_STOP" ] || vp_stop late-failed "код $rc"
}
trap on_exit EXIT

# Переустановка форматирует сохранённый раздел, не создавая его заново: в
# /dev/disk/by-uuid живой системы рядом с новой ссылкой остаётся ссылка от
# прежней файловой системы, и udevadm trigger её не убирает. Сборщик initrd
# берёт первую по алфавиту — до установки пакетов (их хуки тоже собирают
# initrd) убрать каждую ссылку, чьё имя расходится с UUID, прочитанным с
# самого устройства. Не прочитан — ссылка не трогается.
VP_LINKS="${VP_LINKS:-/dev/disk/by-uuid}"
links_sync() {
    udevadm trigger --action=change --subsystem-match=block
    udevadm settle
    for link in "$VP_LINKS"/*; do
        [ -L "$link" ] || continue
        dev="$(readlink -f "$link")"
        now="$(blkid -p -s UUID -o value "$dev" 2>/dev/null)" || continue
        [ -n "$now" ] || continue
        name="${link##*/}"
        if [ "$(echo "$name" | tr 'A-Z' 'a-z')" != "$(echo "$now" | tr 'A-Z' 'a-z')" ]; then
            rm -f "$link"
            out "VP-LINKS: убрана ссылка $name на $dev, на устройстве $now"
        fi
    done
}
links_sync

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
    vp_stop packages-failed "apt с носителя"
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

# Метка для меню носителя: после перезагрузки флешка часто ещё в компьютере,
# и прошивка снова грузит её. Меню находит метку в /boot (вне шифрования,
# есть и на UEFI, и на BIOS) и само загружает установленный шлюз.
{ cat "$HERE/media.info"; echo "installed=$(date -u +%F)"; } > /target/boot/vpn-panel.installed
out "VP-MARK: OK $(sed -n 's/^version=//p' "$HERE/media.info")"

# Рядом с другой системой (и переустановка там же): Windows держит аппаратные
# часы в местном времени — иначе после каждой её загрузки часы шлюза
# сдвигались бы на часовой пояс; меню загрузки видно 5 с: первым и по
# умолчанию шлюз, вторым Windows, штатные пункты Ubuntu — в подменю. Пункты
# пишет свой сценарий grub.d, а название системы (GRUB_DISTRIBUTOR) не
# трогается: из него grub-install и обновления выводят имя папки загрузчика
# EFI/ubuntu, по которой шлюз находят меню носителя и прошивка.
MODE="$(cat /run/vp-install-mode 2>/dev/null || echo erase)"
if [ "$MODE" = beside ] || [ "$MODE" = reinstall ]; then
    printf '0.0 0 0\n0\nLOCAL\n' > /target/etc/adjtime
    mkdir -p /target/etc/default/grub.d /target/etc/grub.d
    cat > /target/etc/default/grub.d/90-vpn-panel-beside.cfg <<'EOF'
# Шлюз рядом с другой системой: меню видно 5 с, другая система в нём.
GRUB_DISABLE_OS_PROBER=false
GRUB_TIMEOUT=5
GRUB_TIMEOUT_STYLE=menu
# Меню по-русски из любого окружения, откуда зовут update-grub.
export LANG=ru_RU.UTF-8
EOF
    cat > /target/etc/grub.d/09_vpn-panel <<'EOF'
#!/bin/sh
# Меню загрузки шлюза, установленного рядом с другой системой: первым и по
# умолчанию — шлюз, вторым — Windows, штатные пункты Ubuntu — в подменю ниже
# (его закрывает 99_vpn-panel). Название системы в GRUB_DISTRIBUTOR не
# меняется: из него grub-install и обновления выводят имя папки загрузчика
# EFI/ubuntu, по которой шлюз находят меню носителя и прошивка.
set -e
. "$pkgdatadir/grub-mkconfig_lib"

# Названия — в переменных: подменю открывается одной командой, а язык
# выбирается при загрузке. По-русски, когда загружен шрифт с кириллицей
# (00_header задаёт lang только после loadfont), иначе латиницей.
# Графический режим ядру, как у Ubuntu: текст — только после сбоя загрузки.
cat <<'CFG'
if [ -n "$lang" ]; then
  set vp_gateway='Шлюз VPN Panel'
  set vp_service='Служебные пункты'
else
  set vp_gateway='VPN Panel gateway'
  set vp_service='Service entries'
fi
if [ "${recordfail}" != 1 ]; then set linux_gfx_mode=keep; else set linux_gfx_mode=text; fi
export linux_gfx_mode
CFG

list=
for k in /boot/vmlinuz-*; do
    if grub_file_is_not_garbage "$k"; then
        case $k in *.old) ;; *) list="$list $k" ;; esac
    fi
done
latest="$(echo $list | tr ' ' '\n' | version_sort -r | head -n 1)"
if [ -n "$latest" ]; then
    version="${latest#/boot/vmlinuz-}"
    rel="$(make_system_path_relative_to_its_root /boot)"
    rel="${rel%/}"
    initrd=
    for i in $GRUB_EARLY_INITRD_LINUX_STOCK $GRUB_EARLY_INITRD_LINUX_CUSTOM; do
        [ -e "/boot/$i" ] && initrd="$initrd $rel/$i"
    done
    for i in "initrd.img-$version" "initrd-$version.img" "initramfs-$version.img"; do
        if [ -e "/boot/$i" ]; then
            initrd="$initrd $rel/$i"
            break
        fi
    done
    # Корень на LVM зовётся устройством, иначе по UUID — как у штатного сценария.
    root="$GRUB_DEVICE"
    if [ -n "$GRUB_DEVICE_UUID" ] && [ "$GRUB_DISABLE_LINUX_UUID" != true ] \
        && [ -e "/dev/disk/by-uuid/$GRUB_DEVICE_UUID" ] && ! uses_abstraction "$GRUB_DEVICE" lvm; then
        root="UUID=$GRUB_DEVICE_UUID"
    fi
    gettext_printf "Found linux image: %s\n" "$latest" >&2
    cat <<CFG
menuentry "\$vp_gateway" --class ubuntu --class gnu-linux --class gnu --class os \$menuentry_id_option 'vpn-panel' {
	recordfail
	load_video
	set gfxpayload=\$linux_gfx_mode
	insmod gzio
$(prepare_grub_to_access_device "$GRUB_DEVICE_BOOT" | grub_add_tab)
	linux	$rel/vmlinuz-$version root=$root ro $(echo $GRUB_CMDLINE_LINUX $GRUB_CMDLINE_LINUX_DEFAULT)
CFG
    [ -z "$initrd" ] || printf '\tinitrd\t%s\n' "$(echo $initrd)"
    echo "}"
fi

# Загрузчик Windows лежит в том же разделе UEFI, куда встал загрузчик шлюза.
esp=/boot/efi
if [ -f "$esp/EFI/Microsoft/Boot/bootmgfw.efi" ]; then
    cat <<CFG
menuentry 'Windows' --class windows --class os \$menuentry_id_option 'vpn-panel-windows' {
$(prepare_grub_to_access_device "$("$grub_probe" --target=device "$esp")" | grub_add_tab)
	chainloader /EFI/Microsoft/Boot/bootmgfw.efi
}
CFG
fi

# Подменю без единой команды GRUB не принимает, отсюда true.
cat <<'CFG'
submenu "$vp_service" $menuentry_id_option 'vpn-panel-service' {
	true
CFG
EOF
    cat > /target/etc/grub.d/99_vpn-panel <<'EOF'
#!/bin/sh
# Закрывает подменю служебных пунктов, открытое сценарием 09_vpn-panel.
[ -x /etc/grub.d/09_vpn-panel ] && echo '}'
exit 0
EOF
    chmod 0755 /target/etc/grub.d/09_vpn-panel /target/etc/grub.d/99_vpn-panel
    curtin in-target -- update-grub >> "$LOG" 2>&1 || out "VP-BESIDE: меню загрузки не обновилось, подробности выше"
    out "VP-BESIDE: OK mode=$MODE $(cat /run/vp-install-disk 2>/dev/null) entries=$(grep -c '^menuentry' /target/boot/grub/grub.cfg)"
fi

# Самопроверка: каждый UUID, который ждут образы загрузки, есть на дисках.
# Не сошлось — убрать мёртвые ссылки, пересобрать и проверить ещё раз; снова
# не сошлось — система не загрузится, установка останавливается честно.
# Проверить нечем (код 2) — тоже остановка, но со своей причиной.
check_initrd() {
    rc=0
    res="$(sh "$HERE/initrd-check.sh")" || rc=$?
    if [ "$rc" -eq 2 ]; then
        out "VP-INITRD: FAIL не проверен — $res"
        vp_stop initrd-unchecked "$res"
    fi
    return "$rc"
}
if ! check_initrd; then
    out "VP-INITRD: повтор — $res"
    links_sync
    curtin in-target -- update-initramfs -u -k all >> "$LOG" 2>&1
    if ! check_initrd; then
        out "VP-INITRD: FAIL $res"
        vp_stop initrd-stale "$res"
    fi
fi
out "VP-INITRD: OK $res"
