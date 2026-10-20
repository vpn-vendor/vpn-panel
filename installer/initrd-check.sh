#!/bin/sh
# Самопроверка образов загрузки установленной системы: каждый UUID, который
# initrd ждёт или открывает (хуки ожидания, crypttab, cmdline, юниты), обязан
# быть на дисках. Список берётся из самого initrd, а не из нашего знания
# о разделах: новый режим или раздел правок здесь не требует.
# Выход: 0 — всё на месте; 1 — чего-то нет (UUID печатаются); 2 — проверять
# нечем или не с чем (пустая проверка — тоже провал, а не зелёный).
set -u
TARGET="${VP_TARGET:-/target}"
# Как остальные шаги зовут команды внутри установленной системы.
IN_TARGET="${VP_IN_TARGET:-curtin in-target --}"
# Каталог распаковки — вне /run, /dev, /proc и /sys: curtin in-target
# подключает их внутрь системы из живой, и созданное снаружи там не видно.
INNER=/var/tmp/vp-initrd-check
WORK="$TARGET$INNER"

have=" $(blkid -s UUID -o value 2>/dev/null | tr 'A-Z' 'a-z' | tr '\n' ' ') "
images=0
seen=0
missing=""
for img in "$TARGET"/boot/initrd.img-*; do
    [ -f "$img" ] || continue
    images=$((images + 1))
    rm -rf "$WORK"
    mkdir -p "$WORK"
    rel="/boot/${img##*/}"
    # Распаковщик — из установленной системы: он того же выпуска, что и
    # сборщик образа. initramfs-tools — запасной путь.
    if ! $IN_TARGET sh -c "cd $INNER && lsinitrd --unpack '$rel'" > /dev/null 2>&1 \
        && ! $IN_TARGET unmkinitramfs "$rel" "$INNER" > /dev/null 2>&1; then
        echo "не распакован: $rel"
        rm -rf "$WORK"
        exit 2
    fi
    # Имена хуков dracut содержат \x2f: файлы — через -exec, xargs съел бы косые.
    for u in $(find "$WORK/etc" "$WORK/var/lib/dracut" "$WORK/usr/lib/dracut" -type f \
                -exec grep -ahoE '(by-uuid/|UUID=|luks-)[0-9A-Fa-f-]{8,}' {} + 2>/dev/null \
                | sed -E 's#^(by-uuid/|UUID=|luks-)##' | tr 'A-Z' 'a-z' | sort -u); do
        seen=$((seen + 1))
        case "$have" in
            *" $u "*) ;;
            *) missing="$missing $rel:$u" ;;
        esac
    done
done
rm -rf "$WORK"
if [ "$images" -eq 0 ] || [ "$seen" -eq 0 ]; then
    echo "образов: $images, UUID в них: $seen"
    exit 2
fi
if [ -n "$missing" ]; then
    echo "нет на дисках:$missing"
    exit 1
fi
echo "образов: $images, UUID в них: $seen, все на дисках"
