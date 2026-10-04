#!/bin/sh
# После штатного шифрования установщика (AES-256-XTS, argon2id), до первой
# загрузки и до появления данных: без AES-NI перешифровать том на adiantum;
# TRIM флагом в заголовке и сразу по всему свободному месту. Ключа
# восстановления нет: забытый пароль — переустановка и импорт настроек.
set -eu
KEY="${VP_KEY_FILE:?}"
CIPHER=xchacha12,aes-adiantum-plain64
# Время: человеку достаточно видеть ход перешифровки раз в полминуты.
PROGRESS_SECONDS=30
LOG="${VP_LOG:?}"
out() { echo "vpn-panel: $*" | tee -a "$LOG"; }
D="$(lsblk -pnro NAME,FSTYPE | awk '$2=="crypto_LUKS"{print $1; exit}')"
[ -n "$D" ] || { out "VP-REENC: FAIL no LUKS volume"; exit 1; }
NAME="$(dmsetup ls --target crypt | awk 'NR==1{print $1}')"
out "VP-T1: $(cryptsetup luksDump "$D" | grep -E 'cipher:|Cipher key:|PBKDF:' | tr -s ' \t' ' ' | tr '\n' ';')"
t0=$(date +%s)
if grep -qw aes /proc/cpuinfo; then
    MODE=kept
else
    MODE=adiantum
    # Скорость и остаток времени cryptsetup считает сам по фактическому ходу.
    # В пакетном режиме ход не печатается; без терминала на входе вопросов нет.
    # Ход идёт в журнал установщика — его видно в окне установки.
    LC_ALL=C cryptsetup reencrypt --cipher "$CIPHER" --key-size 256 \
        --progress-frequency "$PROGRESS_SECONDS" --key-file "$KEY" "$D" < /dev/null
    # Модули шифра — по именам алгоритмов, а не файлов: имена модулей меняются
    # от ядра к ядру, а без них initramfs не откроет диск после обновления.
    mods=""
    for alg in $(printf '%s' "${CIPHER%-*}" | tr ',-' '  '); do
        mods="$mods crypto-$alg"
    done
    mkdir -p /target/etc/dracut.conf.d
    printf 'add_drivers+=" %s "\n' "${mods# }" > /target/etc/dracut.conf.d/90-vpn-panel-disk-cipher.conf
fi
t1=$(date +%s)
cryptsetup refresh --allow-discards --persistent --key-file "$KEY" "$NAME"
# Перешифровка записала каждый блок: до первого fstrim по таймеру SSD считает
# диск заполненным. Свободное место ФС и свободные экстенты группы томов
# возвращаются сразу. Диск без TRIM (старый HDD) — не ошибка установки.
TRIM=unsupported
CMAX="$(lsblk -bdnro DISC-MAX "/dev/mapper/$NAME")"
if [ -n "$CMAX" ] && [ "$CMAX" != "0" ]; then
    # Тома группы подняты до включения TRIM и помнят прежний запрет. LVM
    # одинаковую таблицу не перезагружает — перезагрузить её напрямую, тогда
    # ядро заново возьмёт возможности нижнего устройства.
    for lv in $(lsblk -nro NAME,TYPE "/dev/mapper/$NAME" | awk '$2=="lvm"{print $1}'); do
        dmsetup table "$lv" | dmsetup reload "$lv"
        dmsetup resume "$lv"
    done
    out "VP-TRIM: stack $(lsblk -snro NAME,DISC-MAX "$(findmnt -no SOURCE /target)" | tr '\n' ';')"
    if trimmed="$(LC_ALL=C fstrim -v /target 2>&1)"; then
        out "VP-TRIM: $trimmed"
    else
        out "VP-TRIM: FAIL $trimmed"
        TRIM=failed
    fi
    for vg in $(pvs --noheadings -o vg_name "/dev/mapper/$NAME"); do
        if [ "$(vgs --noheadings -o vg_free_count "$vg" | tr -d ' ')" != "0" ]; then
            lvcreate --yes --wipesignatures n --zero n -l 100%FREE -n vp-trim "$vg" > /dev/null
            blkdiscard "/dev/$vg/vp-trim"
            lvremove --yes "$vg/vp-trim" > /dev/null
            out "VP-TRIM: vg $vg free extents discarded"
        fi
    done
    [ "$TRIM" = failed ] || TRIM=done
fi
curtin in-target -- update-initramfs -u -k all > /dev/null
out "VP-REENC: OK mode=$MODE dev=$D seconds=$((t1 - t0)) name=$NAME trim=$TRIM"
