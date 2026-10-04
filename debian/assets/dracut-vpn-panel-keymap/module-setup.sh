#!/bin/bash
# Экран пароля диска — на английской раскладке при любой раскладке системы.
# Экран пароля переводит клавиши по XKBLAYOUT из файла раскладки внутри
# initramfs, а туда попадает раскладка системы, выбранная уже после задания
# пароля. Модуль выполняется после модулей экрана и кладёт вместо неё
# английскую; раскладка рабочего стола и консоли после загрузки не меняется.

check() {
    return 0
}

depends() {
    return 0
}

install() {
    mkdir -p "$initdir/etc/default"
    rm -f "$initdir/etc/default/keyboard" "$initdir/etc/vconsole.conf"
    printf '%s\n' 'XKBMODEL="pc105"' 'XKBLAYOUT="us"' 'XKBVARIANT=""' 'XKBOPTIONS=""' \
        > "$initdir/etc/default/keyboard"
    ln -s default/keyboard "$initdir/etc/vconsole.conf"
}
