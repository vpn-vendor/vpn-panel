# Источник обновлений и открытый ключ.
INSTALL_PARTS += install-updates
.PHONY: install-updates
install-updates:
	# Источник обновлений и открытый ключ кладёт сам пакет.
	# Без ключа источник не ставится: без проверки подписи нельзя.
	if [ -f debian/assets/vpn-panel.asc ]; then \
		install -D -m 0644 debian/assets/vpn-panel.asc debian/vpn-panel/usr/share/keyrings/vpn-panel.asc; \
	else \
		echo "ВНИМАНИЕ: открытого ключа нет — пакет собран без ключа проверки"; \
	fi
	# Источник кладётся, только когда репозиторий уже работает,
	# иначе apt у клиента ругается на недоступный источник.
	if [ -f debian/assets/vpn-panel.asc ] && [ "$$APT_REPO_LIVE" = "1" ]; then \
		install -D -m 0644 debian/assets/vpn-panel.sources debian/vpn-panel/usr/share/vpn-panel/vpn-panel.sources; \
	else \
		echo "ВНИМАНИЕ: источник обновлений не включён в пакет (APT_REPO_LIVE не задан)"; \
	fi
