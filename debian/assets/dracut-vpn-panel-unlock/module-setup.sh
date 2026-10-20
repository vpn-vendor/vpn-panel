#!/bin/bash
# Запрос пароля диска по-русски, когда заставка не рисует. Без видеодрайвера
# заставка жива, но печатает текст, и человек видел бы английскую строку
# systemd. Модуль кладёт в initramfs агента пароля панели, шрифт с кириллицей
# и свою пару юнитов вместо штатного консольного агента; при рисующей
# заставке агент уступает ей сам.

check() {
    return 0
}

depends() {
    echo systemd-ask-password
    return 0
}

install() {
    local agent=/usr/libexec/vpn-panel/vpn-agent
    # Без агента штатный путь остаётся нетронутым.
    [[ -x "${dracutsysrootdir-}$agent" ]] || return 0
    inst "$agent"
    # setfont распаковывает сжатые шрифты внешней командой gzip.
    inst_multiple -o setfont gzip systemctl
    inst_multiple -o /usr/share/consolefonts/Uni2-TerminusBold14.psf.gz \
        /usr/share/consolefonts/Uni2-TerminusBold16.psf.gz \
        /usr/share/consolefonts/Uni2-TerminusBold18x10.psf.gz \
        /usr/share/consolefonts/Uni2-TerminusBold20x10.psf.gz \
        /usr/share/consolefonts/Uni2-TerminusBold22x11.psf.gz \
        /usr/share/consolefonts/Uni2-TerminusBold24x12.psf.gz \
        /usr/share/consolefonts/Uni2-TerminusBold28x14.psf.gz \
        /usr/share/consolefonts/Uni2-TerminusBold32x16.psf.gz
    inst_simple "$moddir/vpn-panel-disk-unlock.path" "$systemdsystemunitdir/vpn-panel-disk-unlock.path"
    inst_simple "$moddir/vpn-panel-disk-unlock.service" "$systemdsystemunitdir/vpn-panel-disk-unlock.service"
    $SYSTEMCTL -q --root "$initdir" enable vpn-panel-disk-unlock.path
    # Штатный консольный агент печатал бы английскую строку рядом с нашей;
    # при сбое нашего агента он возвращается (OnFailure юнита).
    rm -f "$initdir$systemdsystemunitdir/sysinit.target.wants/systemd-ask-password-console.path"
}
