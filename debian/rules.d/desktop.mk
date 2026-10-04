# Карточка в центрах приложений: значок, ярлык, описание.
INSTALL_PARTS += install-desktop
.PHONY: install-desktop
install-desktop:
	# Карточка в центрах приложений: значок, ярлык, AppStream.
	install -D -m 0644 debian/assets/vpn-panel.svg debian/vpn-panel/usr/share/icons/hicolor/scalable/apps/vpn-panel.svg
	install -D -m 0644 debian/assets/vpn-panel.desktop debian/vpn-panel/usr/share/applications/vpn-panel.desktop
	# Список выпусков берётся из changelog, чтобы не отставал.
	bash scripts/metainfo-gen.sh > debian/build/com.vpn_vendor.panel.metainfo.xml
	install -D -m 0644 debian/build/com.vpn_vendor.panel.metainfo.xml debian/vpn-panel/usr/share/metainfo/com.vpn_vendor.panel.metainfo.xml
	# Растровые значки из того же SVG: магазины приложений вектор не берут.
	# Нет конвертера — ошибка сборки, а не тихий пропуск.
	command -v rsvg-convert >/dev/null || { echo "нет rsvg-convert (пакет librsvg2-bin)"; exit 1; }
	for size in 64 128 256; do \
		rsvg-convert -w $$size -h $$size debian/assets/vpn-panel.svg \
			-o debian/build/vpn-panel-$$size.png; \
		install -D -m 0644 debian/build/vpn-panel-$$size.png \
			debian/vpn-panel/usr/share/icons/hicolor/$${size}x$${size}/apps/vpn-panel.png; \
	done
