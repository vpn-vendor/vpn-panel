# Первая настройка Ubuntu: три экрана вместо восьми и без второго круга после входа.
INSTALL_PARTS += install-first-setup
.PHONY: install-first-setup
install-first-setup:
	# Список пропускаемых страниц; в /etc — чтобы обновление Ubuntu его не трогало.
	install -D -m 0644 debian/assets/gnome-initial-setup-vendor.conf \
		debian/vpn-panel/etc/gnome-initial-setup/vendor.conf
	# Второй круг вопросов после входа и «что нового» после обновления выпуска:
	# пользовательские юниты замаскированы для всех — ссылка на /dev/null в /etc
	# переживает обновление пакета gnome-initial-setup.
	mkdir -p debian/vpn-panel/etc/systemd/user
	ln -s /dev/null debian/vpn-panel/etc/systemd/user/gnome-initial-setup-first-login.service
	ln -s /dev/null debian/vpn-panel/etc/systemd/user/gnome-initial-setup-upgrade-login.service
	# Местоположение и отчёты выключены по умолчанию; схемы собирает триггер glib.
	install -D -m 0644 debian/assets/vpn-panel.gschema.override \
		debian/vpn-panel/usr/share/glib-2.0/schemas/90_vpn-panel.gschema.override
	# Отчёты об ошибках: пакет whoopsie своего файла не ставит, наш — conffile,
	# выбор человека в «Параметрах» обновление пакета не трогает.
	install -D -m 0644 debian/assets/whoopsie.default debian/vpn-panel/etc/default/whoopsie
