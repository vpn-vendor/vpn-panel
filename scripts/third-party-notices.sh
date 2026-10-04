#!/usr/bin/env bash
# Сбор обязательных уведомлений о копирайте модулей, вкомпилированных в бинарник.
#
# Источник истины — сам бинарник, а не go.mod: `go version -m` перечисляет
# ровно те модули, которые попали в сборку. Список из go.mod был бы шире
# правды и включал бы то, чего в продукте нет.
#
# Использование: third-party-notices.sh <бинарник> [ещё бинарники...] > NOTICES
set -euo pipefail

[ $# -ge 1 ] || { echo "использование: third-party-notices.sh <бинарник>..." >&2; exit 2; }

CACHE="$(go env GOMODCACHE)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for bin in "$@"; do
    go version -m "$bin" | awk '$1 == "dep" || $1 == "=>" {print $2"@"$3}'
done | sort -u | grep -v '^$' > "$TMP/mods"

cat <<'HEADER'
УВЕДОМЛЕНИЯ О КОМПОНЕНТАХ СТОРОННИХ АВТОРОВ
THIRD-PARTY NOTICES

В состав программы входят перечисленные ниже компоненты, распространяемые их
правообладателями на условиях свободных лицензий разрешительного типа. Ниже
приведены обязательные уведомления о копирайте и полные тексты лицензий.

Third-party components listed below are included in this program under
permissive open-source licenses. Required copyright notices and full license
texts follow.

HEADER

missing=0
while read -r mod; do
    dir="$CACHE/$(echo "${mod%@*}" | sed 's/\([A-Z]\)/!\l\1/g')@${mod##*@}"
    lic="$(find "$dir" -maxdepth 2 \( -iname 'LICENSE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) 2>/dev/null | sort | head -3)"
    if [ -z "$lic" ]; then
        missing=$((missing + 1))
        printf '=== %s ===\nЛицензия не найдена в кэше модулей — проверить вручную.\n\n' "$mod"
        continue
    fi
    printf '=== %s ===\n' "$mod"
    for f in $lic; do cat "$f"; echo; done
    echo
done < "$TMP/mods"

# Встроенные наборы данных: рядом с файлом лежит .LICENSE, первая строка —
# название компонента.
while read -r lic; do
    printf '=== %s ===\n' "$(head -n 1 "$lic")"
    tail -n +2 "$lic"
    echo
done < <(find internal -name '*.LICENSE' | sort)

count=$(wc -l < "$TMP/mods")
echo "Всего компонентов: $count" >&2
[ "$missing" -eq 0 ] || echo "ВНИМАНИЕ: без найденной лицензии: $missing — собрать вручную" >&2
