#!/usr/bin/env bash
# Убирает комментарии из клиентских ассетов и шаблонов внутри каталога
# сборки пакета: отгруженные CSS/JS/шаблоны не должны нести комментариев.
set -euo pipefail
DIR="$1"

find "$DIR" -type f \( -name '*.css' -o -name '*.js' \) -print0 |
  while IFS= read -r -d '' f; do
    perl -0777 -i -pe 's{/\*.*?\*/}{}gs; s{^[ \t]*//.*$}{}gm; s{\n{3,}}{\n\n}g' "$f"
  done

find "$DIR" -type f -name '*.svg' -print0 |
  while IFS= read -r -d '' f; do
    perl -0777 -i -pe 's{<!--.*?-->\s*}{}gs' "$f"
  done

find "$DIR" -type f -name '*.tmpl' -print0 |
  while IFS= read -r -d '' f; do
    perl -0777 -i -pe 's{<!--.*?-->}{}gs; s{\{\{/\*.*?\*/\}\}}{}gs; s{\n{3,}}{\n\n}g' "$f"
  done
