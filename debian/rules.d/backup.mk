# Код для копии настроек: команда, окно и ярлык.
INSTALL_PARTS += install-backup
.PHONY: install-backup
install-backup:
	install -D -m 0644 debian/assets/vpn-panel-backup-code.desktop debian/vpn-panel/usr/share/applications/vpn-panel-backup-code.desktop
	install -D -m 0755 debian/wrappers/vpn-panel-backup-code debian/vpn-panel/usr/sbin/vpn-panel-backup-code
	install -D -m 0755 debian/wrappers/vpn-panel-backup-code-show debian/vpn-panel/usr/bin/vpn-panel-backup-code-show
