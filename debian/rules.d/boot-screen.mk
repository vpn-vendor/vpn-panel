# Экран пароля диска: раскладка и тема.
INSTALL_PARTS += install-boot-screen
.PHONY: install-boot-screen
install-boot-screen:
	# Экран пароля — на английской раскладке при любой раскладке системы.
	install -D -m 0644 debian/assets/vpn-panel-unlock-keymap.conf \
		debian/vpn-panel/usr/lib/dracut/dracut.conf.d/90-vpn-panel-unlock-keymap.conf
	install -D -m 0755 debian/assets/dracut-vpn-panel-keymap/module-setup.sh \
		debian/vpn-panel/usr/lib/dracut/modules.d/99vpn-panel-keymap/module-setup.sh
	# Тема экрана пароля: готовые файлы из дерева, темой по умолчанию её делает postinst.
	mkdir -p debian/vpn-panel/usr/share/plymouth/themes/vpn-panel
	install -m 0644 debian/assets/boot-theme/*.plymouth debian/assets/boot-theme/*.script \
		debian/assets/boot-theme/*.png debian/vpn-panel/usr/share/plymouth/themes/vpn-panel/
