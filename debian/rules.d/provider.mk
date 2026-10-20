# Подключение к провайдеру: ожидание карты, пауза повторов, возврат очереди.
INSTALL_PARTS += install-provider
.PHONY: install-provider
install-provider:
	# Свой шаблон юнита PPPoE: в пакете ppp 22.04 родного нет; один юнит на
	# обеих системах. Ожидание карты и растущая пауза — в сценарии.
	install -D -m 0755 debian/assets/vpn-panel-ppp-wait-link \
		debian/vpn-panel/usr/libexec/vpn-panel/ppp-wait-link
	install -D -m 0644 debian/assets/vpn-panel-ppp@.service \
		debian/vpn-panel/usr/lib/systemd/system/vpn-panel-ppp@.service
	# Хук pppd: очередь звонков возвращается на WAN, поднявшийся позже агента.
	install -D -m 0755 debian/assets/ppp-ip-up-vpn-panel \
		debian/vpn-panel/etc/ppp/ip-up.d/50vpn-panel
