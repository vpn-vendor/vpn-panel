# Подключение к провайдеру: ожидание карты, пауза повторов, возврат очереди.
INSTALL_PARTS += install-provider
.PHONY: install-provider
install-provider:
	# Подключение к провайдеру: растущая пауза и без предела частоты стартов,
	# канал офиса не должен сдаваться.
	# Ожидание канального интерфейса PPPoE перед pppd.
	install -D -m 0755 debian/assets/vpn-panel-ppp-wait-link \
		debian/vpn-panel/usr/libexec/vpn-panel/ppp-wait-link
	install -D -m 0644 debian/assets/ppp-vpn-panel.conf \
		debian/vpn-panel/usr/lib/systemd/system/ppp@vpn_panel_wan.service.d/vpn-panel.conf
	# Хук pppd: очередь звонков возвращается на WAN, поднявшийся позже агента.
	install -D -m 0755 debian/assets/ppp-ip-up-vpn-panel \
		debian/vpn-panel/etc/ppp/ip-up.d/50vpn-panel
