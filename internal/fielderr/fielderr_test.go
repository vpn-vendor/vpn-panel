package fielderr

import "testing"

func TestPaths(t *testing.T) {
	var inner List
	inner.Add("probe_target", "неверный адрес")
	var l List
	l.Under(Index("profiles", 1), inner)
	l.Add("", "общая ошибка")
	if !l.Has("profiles[1].probe_target") || l[0].Error() != "profiles[1].probe_target: неверный адрес" {
		t.Fatalf("путь вложенной ошибки: %+v", l)
	}
	if l.First() != "неверный адрес" || l[1].Error() != "общая ошибка" {
		t.Fatalf("текст для формы: %q, %q", l.First(), l[1].Error())
	}
	if (List{}).Err() != nil || l.Err() == nil {
		t.Fatal("Err: пустой список — nil, непустой — ошибка")
	}
	if Join("", "a") != "a" || Join("a", "[2]") != "a[2]" || Join("a", "b") != "a.b" {
		t.Fatal("Join")
	}
}

func TestRow(t *testing.T) {
	if Row("labels", 3, "52:54:00:12:34:21") != "labels[52:54:00:12:34:21]" || Row("interfaces", 0, "ens3.100") != "interfaces[ens3.100]" {
		t.Fatal("путь по ключу")
	}
	if Row("x", 2, "") != "x[2]" || Row("x", 2, "a]b") != "x[2]" {
		t.Fatal("без годного ключа — номер строки")
	}
}
