#!/usr/bin/env bash
# Проверка дерева на личные данные: почтовые адреса, приватные ключи,
# домашние пути. Правила — общие формы, а не значения: реальных адресов,
# ключей и путей в этом файле нет. Вывод — только место (файл:строка),
# без значения, поэтому лог не становится утечкой.
set -euo pipefail

git rev-parse --show-toplevel >/dev/null 2>&1 || { echo "check-leaks: пропущено (вне git)"; exit 0; }
cd "$(git rev-parse --show-toplevel)"

tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT

# Допустимые пути домашних папок — из списка рядом со сценарием, если он
# есть: строка — выражение. Без списка не допускается ни один.
ALLOW=""
[ -f scripts/check-leaks.allow ] && ALLOW="$(grep -vE '^[[:space:]]*(#|$)' scripts/check-leaks.allow | paste -sd'|')"

# Допустимые адреса: имена служб, служебные адреса хостинга кода и примеры.
# Свои — из списка рядом со сценарием, если он есть.
MAIL_OK='@vpn-panel\.service|@N\.service|@github\.com|@users\.noreply\.github\.com|example\.'
[ -f scripts/check-leaks.mail ] && MAIL_OK="$MAIL_OK|$(grep -vE '^[[:space:]]*(#|$)' scripts/check-leaks.mail | paste -sd'|')"

scan() { # $1 — категория; со stdin читает вывод grep -n, пишет "  файл:строка [категория]"
  local c="$1" l
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    printf '  %s [%s]\n' "$(printf '%s' "$l" | cut -d: -f1,2)" "$c"
  done
}

# Отслеживаемые и новые, ещё не добавленные файлы (кроме игнорируемых): гейт
# идёт до коммита и обязан видеть то, что в коммит попадёт.
F="$(git ls-files --cached --others --exclude-standard)"
{
  printf '%s\n' "$F" | xargs -r grep -nIE '[[:alnum:]._%+-]+@[[:alnum:].-]+\.[[:alpha:]]{2,}' 2>/dev/null \
    | grep -vE "$MAIL_OK" \
    | scan почта || true
  printf '%s\n' "$F" | xargs -r grep -nI 'BEGIN [A-Z ]*PRIVATE KEY' 2>/dev/null | scan ключ || true
  printf '%s\n' "$F" | xargs -r grep -nIoE '/home/[[:alnum:]._-]+' 2>/dev/null \
    | { [ -n "$ALLOW" ] && grep -vE "$ALLOW" || cat; } | scan путь || true
} > "$tmp"

if [ -s "$tmp" ]; then
  cat "$tmp" >&2
  echo >&2
  echo "Найдены личные данные — уберите их из дерева перед коммитом." >&2
  exit 1
fi
echo "check-leaks: чисто"
