# Остановка установки с причиной по-русски. Подключается из early.sh и
# late.sh (точкой); до подключения задан VP_REASONS — путь к reasons.tsv.
# Строка человеку ложится в файл живой системы и в поток событий
# установщика: только его окно ошибки показывает по «Показать журнал».

VP_STOP=/run/vp-stop-reason

# $1 — имя причины, дальше — подстановки {1}, {2}.
vp_reason() {
    awk -F '\t' -v id="$1" -v a1="${2:-}" -v a2="${3:-}" '
        $1 == id {
            line = ($2 == "late" ? "Установка не завершена: " : "Установка не начата: ") $3 " " $4
            if ($2 != "late") line = line " Диск не тронут, компьютер можно выключить."
            line = line " Если не помогло, сфотографируйте это окно: что делать дальше, сказано в ПРОЧТИ-МЕНЯ.txt на флешке."
            gsub(/\{1\}/, a1, line)
            gsub(/\{2\}/, a2, line)
            print line
            found = 1
        }
        END { exit !found }' "$VP_REASONS"
}

# Имена потоков событий — внутренняя деталь установщика: нет потока —
# причина остаётся в файле.
vp_announce() {
    for id in $(journalctl -b -q -F SYSLOG_IDENTIFIER 2>/dev/null | grep '^subiquity_event\.'); do
        logger -t "$id" "$1" || true
    done
}

# $1 — имя причины, $2 — подробность только для журнала, дальше — подстановки.
vp_stop() {
    id="$1"
    detail="${2:-}"
    if [ $# -ge 2 ]; then shift 2; else shift $#; fi
    text="$(vp_reason "$id" "$@")" || text="Установка остановлена. Начните её заново; если повторится, сфотографируйте это окно."
    printf '%s\n' "$text" > "$VP_STOP"
    echo "vpn-panel: $id: $text${detail:+ ($detail)}" >&2
    vp_announce "$text"
    exit 1
}
