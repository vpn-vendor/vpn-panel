package pathprobe

import (
	"net"
	"testing"
	"time"
)

func TestNumbersFrozen(t *testing.T) {
	if Interval != time.Second || JitterShare != 0.3 || Timeout != 2*time.Second || DownAfter != 5 || UpAfter != 5 || VerdictProbes != 1000 || DSCPEF != 0xb8 {
		t.Fatal("числа пробы изменены")
	}
	for i := 0; i < 1000; i++ {
		if d := NextInterval(); d < 700*time.Millisecond || d > 1300*time.Millisecond {
			t.Fatalf("интервал вне разброса: %v", d)
		}
	}
}

func TestEchoChecksum(t *testing.T) {
	b := buildEcho(7)
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	if uint16(sum) != 0xffff || b[0] != 8 || b[6] != 0 || b[7] != 7 {
		t.Fatalf("пакет эха: %x", b)
	}
}

func TestHysteresis(t *testing.T) {
	var h Hysteresis
	changes := 0
	for i := 0; i < 4; i++ {
		if _, ch := h.Feed(false); ch {
			changes++
		}
	}
	if h.State() != Unknown {
		t.Fatalf("четыре неудачи с подъёма — ещё неизвестно: %v", h.State())
	}
	if st, ch := h.Feed(false); !ch || st != NoAnswer {
		t.Fatalf("пятая неудача с подъёма: %v %v", st, ch)
	}
	if st, ch := h.Feed(true); !ch || st != Up {
		t.Fatalf("первый успех — путь известен: %v %v", st, ch)
	}
	for i := 0; i < 4; i++ {
		if _, ch := h.Feed(false); ch {
			t.Fatal("тревога раньше пяти неудач")
		}
	}
	if st, ch := h.Feed(false); !ch || st != Down {
		t.Fatalf("пятая неудача после успеха — вниз: %v %v", st, ch)
	}
	for i := 0; i < 4; i++ {
		if _, ch := h.Feed(true); ch {
			t.Fatal("восстановление раньше пяти успехов")
		}
	}
	if st, ch := h.Feed(true); !ch || st != Up {
		t.Fatalf("пятый успех — вверх: %v %v", st, ch)
	}
}

func TestWindowAndQuorum(t *testing.T) {
	var w Window
	if _, enough := w.Loss(); enough {
		t.Fatal("пустое окно — данных мало")
	}
	for i := 0; i < 20; i++ {
		w.Add(i != 3)
	}
	if p, enough := w.Loss(); enough || p != 5 {
		t.Fatalf("20 проб: %v %v — вердикта быть не должно (1 из 20 ничего не доказывает)", p, enough)
	}
	for i := 0; i < VerdictProbes; i++ {
		w.Add(i%100 != 0)
	}
	if p, enough := w.Loss(); !enough || p != 1 {
		t.Fatalf("1000 проб: %v %v", p, enough)
	}
	if !Quorum([]bool{true, false}, 1) || Quorum([]bool{false, false}, 1) || Quorum([]bool{true}, 0) {
		t.Fatal("k из n")
	}
}

func TestPingLoopback(t *testing.T) {
	rtt, err := Ping(net.ParseIP("127.0.0.1"), 1, Timeout)
	if err != nil {
		t.Skipf("проба петли недоступна здесь: %v", err)
	}
	if rtt <= 0 || rtt > Timeout {
		t.Fatalf("время обхода %v", rtt)
	}
}
