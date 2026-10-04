#!/usr/bin/env bash
# Страж знака: тема экрана пароля и значки собраны из текущих входов (знак,
# сценарий, генераторы, коды подсказок, токены тёмной темы), а значки не
# правились руками. Изменился вход или выход — пересборка генератором, иначе
# гейт красный.
#
#   check-brand.sh                  проверка
#   check-brand.sh --print          отпечаток входов темы
#   check-brand.sh --print-icons    отпечаток входов и выходов значков
set -euo pipefail
cd "$(dirname "$0")/.."
THEME=debian/assets/boot-theme

fingerprint() {
    sha256sum scripts/brand/mark.txt scripts/brand/boot-theme.script.in \
        scripts/brand/gen-boot-theme.py internal/diskcrypt/texts.tsv
    # Из таблицы стилей — только блок тёмной темы: остальные правки CSS тему не меняют.
    awk '/:root\[data-theme="dark"\]/{f=1} f{print} f&&/^}/{exit}' public/css/app.css \
        | sha256sum | sed 's|-$|public/css/app.css (тёмная тема)|'
}

dark_css() {
    awk '/:root\[data-theme="dark"\]/{f=1} f{print} f&&/^}/{exit}' public/css/app.css \
        | sha256sum | sed 's|-$|public/css/app.css (тёмная тема)|'
}

icons() {
    sha256sum scripts/brand/mark.txt scripts/brand/gen-icons.py debian/assets/vpn-panel.svg \
        resources/views/components/brand-mark.tmpl resources/views/components/brand-favicon.tmpl
    dark_css
}

case "${1:-}" in
    --print) fingerprint; exit 0 ;;
    --print-icons) icons; exit 0 ;;
esac

fail=0
if ! diff -u "$THEME/inputs.sha256" <(fingerprint) > /dev/null 2>&1; then
    echo "check-brand: входы темы изменились — пересоберите: python3 scripts/brand/gen-boot-theme.py" >&2
    diff -u "$THEME/inputs.sha256" <(fingerprint) >&2 || true
    fail=1
fi
# У каждого кода подсказки — картинки всех трёх размеров.
while IFS=$'\t' read -r code _; do
    [ -n "$code" ] || continue
    for size in s m l; do
        f="$THEME/text-${code#vp:}-$size.png"
        [ -f "$f" ] || { echo "check-brand: нет $f" >&2; fail=1; }
    done
done < internal/diskcrypt/texts.tsv
if ! diff -u debian/assets/icons.sha256 <(icons) > /dev/null 2>&1; then
    echo "check-brand: значки не совпадают со знаком — пересоберите: python3 scripts/brand/gen-icons.py" >&2
    diff -u debian/assets/icons.sha256 <(icons) >&2 || true
    fail=1
fi
for f in vpn-panel.plymouth vpn-panel.script px-mark.png px-field.png px-line.png px-text.png; do
    [ -f "$THEME/$f" ] || { echo "check-brand: нет $THEME/$f" >&2; fail=1; }
done
if [ "$fail" = 0 ]; then echo "check-brand: тема и значки собраны из текущих входов"; else exit 1; fi
