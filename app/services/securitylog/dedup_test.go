package securitylog

import (
	"strconv"
	"testing"
	"time"
)

func TestBurstFromOneAddressIsOneRow(t *testing.T) {
	d := NewDeduper(time.Minute, 16)
	t0 := time.Unix(1000, 0)
	k := Key{Event: "code_failed", IP: "192.0.2.5"}

	if d.Coalesce(k, t0) {
		t.Fatal("первое событие обязано писаться строкой")
	}
	d.Open(k, 7, t0)
	for i := 1; i <= 500; i++ {
		if !d.Coalesce(k, t0.Add(time.Duration(i)*100*time.Millisecond)) {
			t.Fatalf("повтор %d в окне записан строкой", i)
		}
	}
	if fl := d.Expire(t0.Add(30 * time.Second)); len(fl) != 0 {
		t.Fatal("окно не закончилось, а правка выпущена")
	}
	fl := d.Expire(t0.Add(time.Minute))
	if len(fl) != 1 || fl[0].ID != 7 || fl[0].Extra != 500 {
		t.Fatalf("после окна ожидалась одна правка строки 7 на 500 повторов: %+v", fl)
	}
	if d.Len() != 0 {
		t.Fatal("закрытое окно не удалено")
	}
	if d.Coalesce(k, t0.Add(61*time.Second)) {
		t.Fatal("после окна событие обязано снова писаться строкой")
	}
}

func TestDifferentAddressesAndEventsAreSeparate(t *testing.T) {
	d := NewDeduper(time.Minute, 16)
	t0 := time.Unix(1000, 0)
	d.Open(Key{"code_failed", "192.0.2.1"}, 1, t0)
	if d.Coalesce(Key{"code_failed", "192.0.2.2"}, t0) {
		t.Fatal("другой адрес сведён в чужую строку")
	}
	if d.Coalesce(Key{"setup_denied", "192.0.2.1"}, t0) {
		t.Fatal("другое событие сведено в чужую строку")
	}
}

func TestKeysCeilingFallsBackToOverflowKey(t *testing.T) {
	d := NewDeduper(time.Minute, 8)
	t0 := time.Unix(1000, 0)
	rows := 0
	for i := 0; i < 5000; i++ {
		k := d.Resolve(Key{Event: "code_failed", IP: "10.0." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250)})
		if !d.Coalesce(k, t0) {
			d.Open(k, uint(i+1), t0)
			rows++
		}
	}
	if d.Len() > 9 {
		t.Fatalf("учёт вырос до %d при потолке 8 и одном ключе переполнения", d.Len())
	}
	if rows != 9 {
		t.Fatalf("строк записано %d, ожидалось 9 (8 адресов + ключ переполнения)", rows)
	}
}

func TestAllFlushesOpenWindows(t *testing.T) {
	d := NewDeduper(time.Minute, 16)
	t0 := time.Unix(1000, 0)
	k := Key{"diag_lantest", "192.0.2.9"}
	d.Open(k, 3, t0)
	d.Coalesce(k, t0.Add(time.Second))
	d.Open(Key{"code_failed", "192.0.2.9"}, 4, t0)
	fl := d.All()
	if len(fl) != 1 || fl[0].ID != 3 || fl[0].Extra != 1 {
		t.Fatalf("при остановке теряются повторы или пишутся пустые правки: %+v", fl)
	}
}

func TestClassesAndApprovedNumbers(t *testing.T) {
	for _, e := range []string{"setup_denied", "code_failed", "device_label_proposed", "device_label_throttled", "diag_lantest", "devices_new_throttled"} {
		if ClassOf(e) != Ordinary {
			t.Errorf("%s вызывается без входа и обязан быть обычным", e)
		}
	}
	for _, e := range []string{"code_issued", "device_enrolled", "device_revoked", "devices_reset", "network_apply", "vpn_apply", "security_settings", "retention_settings"} {
		if ClassOf(e) != Critical {
			t.Errorf("%s — действие администратора, обязан быть критичным", e)
		}
	}
	if DedupWindow != time.Minute || DedupKeys != 1024 {
		t.Fatalf("числа сведения изменены: %v %d", DedupWindow, DedupKeys)
	}
}
