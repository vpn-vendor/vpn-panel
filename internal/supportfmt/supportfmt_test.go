package supportfmt

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func testSet(t testing.TB) Set {
	t.Helper()
	set, err := NewSet(Section{ID: "versions", Title: "Версии", MaxLines: 5}, Section{ID: "journal", Title: "Журнал", MaxLines: 100})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func build(t testing.TB, fill func(w *Writer)) []byte {
	t.Helper()
	var b bytes.Buffer
	w := NewWriter(&b, testSet(t), [][2]string{{"собрано", "2026-10-03T12:00:00Z"}, {"версия", "0.3.0"}})
	fill(w)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func check(t testing.TB, data []byte) (*Report, []byte, error) {
	t.Helper()
	var out bytes.Buffer
	rep, err := Check(bytes.NewReader(data), &out, testSet(t), 1<<20)
	return rep, out.Bytes(), err
}

func reason(err error) Reason {
	var r *Rejection
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

func TestWriterOutputIsAccepted(t *testing.T) {
	data := build(t, func(w *Writer) {
		_ = w.Begin("versions")
		w.Line("пакет 0.3.0")
		w.Line("ядро 7.0.0")
		_ = w.Begin("journal")
		w.Line("первая\nвторая\r\nтретья")
		w.Line("== раздел: versions ==")
		w.Line("имя устройства \x1b[31mкрасное\x1b[0m и \u202eобратное")
		w.Line(`обратная \ черта`)
		w.Line(string([]byte{0xff, 0xfe, 'a'}))
	})
	rep, clean, err := check(t, data)
	if err != nil {
		t.Fatalf("файл сборщика отвергнут: %v\n%s", err, data)
	}
	if !bytes.Equal(clean, data) {
		t.Fatal("чистая копия отличается от принятого файла")
	}
	if len(rep.Parts) != 2 || rep.Parts[0].ID != "versions" || rep.Parts[0].Lines != 2 || rep.Parts[1].Lines != 7 {
		t.Fatalf("оглавление: %+v", rep.Parts)
	}
	if len(rep.Header) != 2 {
		t.Fatalf("заголовок: %q", rep.Header)
	}
	for _, bad := range []string{"\x1b", "\u202e", "\r", "\xff"} {
		if bytes.Contains(data, []byte(bad)) {
			t.Fatalf("в файле остался недопустимый знак %q", bad)
		}
	}
	if !bytes.Contains(data, []byte(`\u{1B}[31m`)) || !bytes.Contains(data, []byte(`\xFF\xFEa`)) || !bytes.Contains(data, []byte(`\\ черта`)) {
		t.Fatalf("знаки источника не видны в записи:\n%s", data)
	}
}

func TestSectionLimitIsMarkedNotSilent(t *testing.T) {
	data := build(t, func(w *Writer) {
		_ = w.Begin("versions")
		for i := 0; i < 50; i++ {
			w.Line("строка")
		}
	})
	rep, _, err := check(t, data)
	if err != nil {
		t.Fatalf("обрезанный раздел отвергнут: %v", err)
	}
	if rep.Parts[0].Lines != 5 || !bytes.Contains(data, []byte(truncated)) {
		t.Fatalf("предел раздела: строк %d", rep.Parts[0].Lines)
	}
}

func TestLongLineIsCutOnRuneBoundary(t *testing.T) {
	data := build(t, func(w *Writer) {
		_ = w.Begin("journal")
		w.Line(strings.Repeat("я", MaxLineBytes))
	})
	if _, _, err := check(t, data); err != nil {
		t.Fatalf("длинная строка сборщика отвергнута: %v", err)
	}
	if !utf8.Valid(data) {
		t.Fatal("строка разрезана посреди знака")
	}
}

func TestWriterRefusesUnknownAndRepeated(t *testing.T) {
	var b bytes.Buffer
	w := NewWriter(&b, testSet(t), nil)
	if w.Begin("secrets") == nil {
		t.Fatal("неизвестный раздел принят сборщиком")
	}
	if w.Begin("versions") != nil || w.Begin("versions") == nil {
		t.Fatal("повтор раздела принят сборщиком")
	}
}

func TestBaitsAreRejected(t *testing.T) {
	good := string(build(t, func(w *Writer) {
		_ = w.Begin("versions")
		w.Line("пакет 0.3.0")
		_ = w.Begin("journal")
		w.Line("запись")
	}))
	if _, _, err := check(t, []byte(good)); err != nil {
		t.Fatalf("образец отвергнут: %v", err)
	}
	baits := []struct {
		name string
		data string
		want Reason
	}{
		{"чужой файл", "PK\x03\x04архив", NotOurs},
		{"пустой файл", "", NotOurs},
		{"чужая первая строка", strings.Replace(good, Magic, "VPN-PANEL-SUPPORT 9", 1), NotOurs},
		{"управляющая последовательность", strings.Replace(good, "запись", "за\x1b[2Jпись", 1), BadChar},
		{"знак направления письма", strings.Replace(good, "запись", "за\u202eпись", 1), BadChar},
		{"невидимый знак", strings.Replace(good, "запись", "за\u200bпись", 1), BadChar},
		{"возврат каретки", strings.Replace(good, "запись", "запись\r", 1), BadChar},
		{"табуляция", strings.Replace(good, "запись", "за\tпись", 1), BadChar},
		{"нулевой байт", strings.Replace(good, "запись", "за\x00пись", 1), BadChar},
		{"не UTF-8", strings.Replace(good, "запись", "за\xffпись", 1), BadEncoding},
		{"длинная строка", strings.Replace(good, "запись", strings.Repeat("a", MaxLineBytes+1), 1), LineTooLong},
		{"неизвестный раздел", strings.Replace(good, "== раздел: journal ==", "== раздел: secrets ==", 1), UnknownPart},
		{"повтор раздела", strings.Replace(good, "== раздел: journal ==", "== раздел: versions ==", 1), RepeatedPart},
		{"лишняя строка в разделе", strings.Replace(good, "запись\n", "запись\nещё одна\n", 1), CountsDiffer},
		{"раздел длиннее предела", strings.Replace(strings.Replace(good, "пакет 0.3.0\n", strings.Repeat("x\n", 6), 1), "versions строк: 1", "versions строк: 6", 1), PartTooLong},
		{"раздел в разделе", strings.Replace(good, "запись\n", "== раздел: versions ==\n", 1), BadStructure},
		{"незнакомая разметка", strings.Replace(good, "запись", "== что-то ==", 1), BadStructure},
		{"строка между разделами", strings.Replace(good, "== раздел: journal ==", "вставка\n== раздел: journal ==", 1), BadStructure},
		{"нет завершающей строки", good[:strings.LastIndex(good, fileClose)], Unfinished},
		{"оборван посреди строки", good[:len(good)-3], Unfinished},
		{"неверное число разделов", strings.Replace(good, fileClose+"2", fileClose+"3", 1), CountsDiffer},
		{"данные после конца", good + "хвост\n", TrailingData},
		{"второй файл после конца", good + good, TrailingData},
	}
	for _, b := range baits {
		_, _, err := check(t, []byte(b.data))
		if got := reason(err); got != b.want {
			t.Errorf("%s: отказ %q, ожидался %q (ошибка: %v)", b.name, got, b.want, err)
		}
	}
}

func TestSizeLimit(t *testing.T) {
	data := build(t, func(w *Writer) {
		_ = w.Begin("journal")
		for i := 0; i < 50; i++ {
			w.Line(strings.Repeat("a", 100))
		}
	})
	var out bytes.Buffer
	_, err := Check(bytes.NewReader(data), &out, testSet(t), 1000)
	if reason(err) != TooBig {
		t.Fatalf("предел объёма: %v", err)
	}
}

func TestRejectionCarriesNoFileBytes(t *testing.T) {
	_, _, err := check(t, []byte("ЗЛОЙ-ТЕКСТ\x1b[2J\n"))
	if err == nil || strings.Contains(err.Error(), "ЗЛОЙ") || strings.ContainsRune(err.Error(), 0x1b) {
		t.Fatalf("в отказе текст файла: %q", err)
	}
}

func FuzzCheck(f *testing.F) {
	f.Add(build(f, func(w *Writer) { _ = w.Begin("journal"); w.Line("запись") }))
	f.Add([]byte(Magic + "\n== раздел: journal ==\n== конец: journal строк: 0 ==\n== конец файла: разделов: 1 ==\n"))
	f.Add([]byte("\x1f\x8b\x08\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		rep, clean, err := check(t, data)
		if err != nil {
			return
		}
		if !bytes.Equal(clean, data) {
			t.Fatal("принятый файл и чистая копия различаются")
		}
		for _, r := range string(clean) {
			if r != '\n' && !allowed(r) {
				t.Fatalf("в чистой копии недопустимый знак %U", r)
			}
		}
		if _, _, err := check(t, clean); err != nil || rep == nil {
			t.Fatalf("чистая копия не проходит приём повторно: %v", err)
		}
	})
}

func FuzzWriter(f *testing.F) {
	f.Add("обычная строка", "вторая")
	f.Add("\x1b]0;заголовок\x07", "== конец файла: разделов: 9 ==")
	f.Add(string([]byte{0xc3, 0x28, 0x00}), strings.Repeat("ю", 3000))
	f.Fuzz(func(t *testing.T, a, b string) {
		data := build(t, func(w *Writer) {
			_ = w.Begin("versions")
			w.Line(a)
			_ = w.Begin("journal")
			w.Line(b)
			w.Line(a + b)
		})
		if _, _, err := check(t, data); err != nil {
			t.Fatalf("файл сборщика отвергнут: %v", err)
		}
	})
}

func TestKnownPartsAreConsistent(t *testing.T) {
	set := Known()
	if len(set) != len(Parts) {
		t.Fatalf("разделов %d, в наборе %d", len(Parts), len(set))
	}
	for _, p := range Parts {
		if p.Title == "" {
			t.Errorf("раздел %q без названия", p.ID)
		}
	}
}
