# Программы и статика панели: первым, остальное кладётся рядом.
INSTALL_PARTS += install-base
.PHONY: install-base
install-base:
	install -D -m 0755 debian/build/vpn-panel debian/vpn-panel/usr/sbin/vpn-panel
	install -D -m 0755 debian/build/vpn-agent debian/vpn-panel/usr/sbin/vpn-agent
	mkdir -p debian/vpn-panel/usr/share/vpn-panel
	cp -r public resources debian/vpn-panel/usr/share/vpn-panel/
	# Снять комментарии со статики и проверить её на личные данные.
	bash scripts/strip-comments.sh debian/vpn-panel/usr/share/vpn-panel
	bash scripts/check-leaks.sh debian/vpn-panel
	# Уведомления о копирайте модулей, вкомпилированных в бинарник.
	bash scripts/third-party-notices.sh debian/build/vpn-panel debian/build/vpn-agent \
		> debian/build/THIRD-PARTY-NOTICES
