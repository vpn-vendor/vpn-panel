# Консольные обёртки входа и вход с рабочего стола сервера.
INSTALL_PARTS += install-console
.PHONY: install-console
install-console:
	# Вход с рабочего стола сервера: ярлык и правило подтверждения прав.
	install -D -m 0644 debian/assets/vpn-panel-login.desktop debian/vpn-panel/usr/share/applications/vpn-panel-login.desktop
	install -D -m 0644 debian/assets/com.vpn_vendor.panel.policy debian/vpn-panel/usr/share/polkit-1/actions/com.vpn_vendor.panel.policy
	# Консольные обёртки — корень доверия входа.
	install -D -m 0755 debian/wrappers/vpn-panel-code debian/vpn-panel/usr/sbin/vpn-panel-code
	install -D -m 0755 debian/wrappers/vpn-panel-reset debian/vpn-panel/usr/sbin/vpn-panel-reset
	install -D -m 0755 debian/wrappers/vpn-panel-desktop-login debian/vpn-panel/usr/sbin/vpn-panel-desktop-login
	install -D -m 0755 debian/wrappers/vpn-panel-login debian/vpn-panel/usr/bin/vpn-panel-login
