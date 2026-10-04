package metrics

import "testing"

func TestValidateSection(t *testing.T) {
	good := Section{Master: "on", Sources: map[string]string{"net.links": "memory", "proc.cpu": "off"}}
	if errs := ValidateSection(good); len(errs) > 0 {
		t.Fatalf("годный раздел отвергнут: %v", errs.Err())
	}
	for _, c := range []struct {
		name string
		v    Section
		path string
	}{
		{"выключатель", Section{Master: "maybe"}, "master"},
		{"пауза не переносится", Section{Master: "pause:1893456000"}, "master"},
		{"неизвестный источник", Section{Master: "on", Sources: map[string]string{"disk.smart": "on"}}, "sources.disk.smart"},
		{"состояние источника", Section{Master: "on", Sources: map[string]string{"qos.voice": "sometimes"}}, "sources.qos.voice"},
	} {
		if !ValidateSection(c.v).Has(c.path) {
			t.Errorf("%s: нет ошибки поля %q: %v", c.name, c.path, ValidateSection(c.v).Err())
		}
	}
	if len(SourceNames()) < 5 {
		t.Errorf("реестр источников: %v", SourceNames())
	}
}
