package diag

import (
	"strings"
	"testing"
)

func TestLabelFieldsTouchOnlyGiven(t *testing.T) {
	pub, empty := "ПК Ирины", ""
	got, err := labelFields(LabelUpdate{Public: &pub, Owner: &empty})
	if err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{"note", "label", "location"} {
		if _, ok := got[col]; ok {
			t.Errorf("непереданное поле %q попало в запись", col)
		}
	}
	if got["public_label"] != pub {
		t.Errorf("видимая подпись: %v", got["public_label"])
	}
	if v, ok := got["owner"]; !ok || v != "" {
		t.Errorf("явно пустое поле не очищается: %v %v", v, ok)
	}
	if got, _ := labelFields(LabelUpdate{}); len(got) != 0 {
		t.Errorf("пустое обновление пишет %v", got)
	}
}

func TestLabelFieldsValidatesGiven(t *testing.T) {
	long := strings.Repeat("я", MaxNote+1)
	if _, err := labelFields(LabelUpdate{Note: &long}); err == nil || !strings.HasPrefix(err.Error(), "заметка: ") {
		t.Errorf("слишком длинная заметка принята или ошибка не называет поле: %v", err)
	}
}
