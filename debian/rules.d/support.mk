# Сведения для поддержки: команда, окно и ярлык.
INSTALL_PARTS += install-support
.PHONY: install-support
install-support:
	install -D -m 0644 debian/assets/vpn-panel-support.desktop debian/vpn-panel/usr/share/applications/vpn-panel-support.desktop
	install -D -m 0755 debian/wrappers/vpn-panel-support debian/vpn-panel/usr/sbin/vpn-panel-support
	install -D -m 0755 debian/wrappers/vpn-panel-support-show debian/vpn-panel/usr/bin/vpn-panel-support-show
