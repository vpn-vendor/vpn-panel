# Защита раньше сети: сценарий загрузки и аварийный запрет выхода.
INSTALL_PARTS += install-boot-guard
.PHONY: install-boot-guard
install-boot-guard:
	# Защита раньше сети: сценарий и аварийный запрет выхода.
	install -D -m 0755 debian/assets/vpn-panel-firewall-boot \
		debian/vpn-panel/usr/libexec/vpn-panel/firewall-boot
	install -D -m 0644 debian/assets/vpn-panel-lockdown.nft \
		debian/vpn-panel/usr/share/vpn-panel/lockdown.nft
