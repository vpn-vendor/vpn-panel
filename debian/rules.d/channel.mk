# Программа канала: перезапуск после падения и каталог под сокет.
INSTALL_PARTS += install-channel
.PHONY: install-channel
install-channel:
	# Второй протокол: перезапуск после падения и каталог в /run под сокет.
	install -D -m 0644 debian/assets/openvpn-client-vpn-panel.conf \
		debian/vpn-panel/usr/lib/systemd/system/openvpn-client@vpn-panel.service.d/vpn-panel.conf
