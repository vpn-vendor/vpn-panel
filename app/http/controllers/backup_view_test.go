package controllers

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/app/services/backup"
	"github.com/vpn-vendor/vpn-panel-core/app/services/restore"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
)

func TestBackupPlanSpeaksHuman(t *testing.T) {
	p := &backup.Plan{Sections: []backup.SectionPlan{
		{Name: settings.SectionRetention, InFile: true, Changes: []backup.Change{{Path: "journal_days", Kind: backup.Changed}, {Path: "trust_keep_days", Kind: backup.Changed}}},
		{Name: settings.SectionVPN, InFile: true, Changes: []backup.Change{{Path: "profiles[офис]", Kind: backup.Added, Item: "офис", Dangerous: true, Title: "Подключения VPN", Warn: "меняет сервер"}}},
		{Name: settings.SectionQoS},
	}}
	rows := sectionRows(p)
	if rows[0].Title != "Хранение данных" || rows[0].State != "изменится: 2 настройки" {
		t.Fatalf("простые поля: %+v", rows[0])
	}
	if rows[1].Title != "VPN" || len(rows[1].Items) != 1 || rows[1].Items[0] != "«офис» — добавится" {
		t.Fatalf("строки таблиц: %+v", rows[1])
	}
	if !rows[2].Absent {
		t.Fatalf("раздел не из файла: %+v", rows[2])
	}
	for _, r := range rows {
		if strings.Contains(r.State+strings.Join(r.Items, ""), "_") {
			t.Fatalf("технический путь на странице: %+v", r)
		}
	}
	d := dangerRows(p)
	if len(d) != 1 || d[0].Title != "Подключения VPN" || d[0].Item != "офис" || d[0].Kind != "добавится" || d[0].Name != "danger_0" {
		t.Fatalf("опасные строки: %+v", d)
	}
}

func TestCardQuestionsOfferEveryCardWithFacts(t *testing.T) {
	pv := &restore.Preview{
		Ask: []backup.Ref{{Card: backup.Card{Name: "enp1s0"}, Row: map[string]json.RawMessage{"role": json.RawMessage(`"wan"`)}}},
		Cards: []restore.CardFacts{{Card: backup.Card{Name: "eth0"}, Link: true, Provider: true, SpeedMbit: 1000},
			{Card: backup.Card{Name: "eth1"}}},
		Choice: map[string]string{"enp1s0": "eth0"},
	}
	q := cardQuestions(pv)
	if len(q) != 1 || q[0].Role != "смотрела в интернет" || q[0].Select.Name != "card_enp1s0" || q[0].Select.Value != "eth0" {
		t.Fatalf("%+v", q)
	}
	if len(q[0].Select.Options) != 3 || !strings.Contains(q[0].Select.Options[1].Label, "провайдер ответил") ||
		!strings.Contains(q[0].Select.Options[2].Label, "кабеля нет") {
		t.Fatalf("варианты с фактами: %+v", q[0].Select.Options)
	}
}
