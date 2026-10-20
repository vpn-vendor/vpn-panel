package network

import (
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

func CloneConflict(mac, card string, st *netstatus.Status, neigh []netstatus.Neighbor) string {
	if mac == "" {
		return ""
	}
	if st != nil {
		for _, i := range st.Interfaces {
			if i.Name != card && (i.MAC == mac || i.Presented == mac) {
				return "Адрес " + mac + " уже у карты «" + i.Name + "» этого шлюза. Впишите адрес старого роутера: он напечатан на его наклейке."
			}
		}
	}
	for _, n := range neigh {
		if n.MAC == mac {
			return "Устройство с адресом " + mac + " сейчас отвечает в сети (карта «" + n.Dev + "»): похоже, старый роутер ещё подключён. " +
				"Отключите от него кабель провайдера и примените снова."
		}
	}
	return ""
}
