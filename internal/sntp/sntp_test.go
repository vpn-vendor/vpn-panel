package sntp

import (
	"encoding/binary"
	"testing"
	"time"
)

func reply(t1 time.Time, recvDelay, skew time.Duration) []byte {
	b := make([]byte, PacketSize)
	b[0] = 0<<6 | 4<<3 | 4
	b[1] = 2
	put := func(off int, tm time.Time) {
		secs := uint32(tm.Unix() + unixEpochOffset) //nolint:gosec
		frac := uint32(float64(tm.Nanosecond()) / 1e9 * (1 << 32))
		binary.BigEndian.PutUint32(b[off:], secs)
		binary.BigEndian.PutUint32(b[off+4:], frac)
	}
	put(32, t1.Add(recvDelay).Add(skew))
	put(40, t1.Add(recvDelay).Add(skew))
	return b
}

func TestOffsetDetectsSkew(t *testing.T) {
	t1 := time.Unix(1788600000, 0)

	got, err := Offset(reply(t1, 30*time.Millisecond, time.Hour), t1, t1.Add(60*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if d := got - time.Hour; d > time.Second || d < -time.Second {
		t.Fatalf("поправка %s, ожидался примерно час", got)
	}
	if got < Suspicious {
		t.Fatal("час расхождения обязан считаться подозрительным")
	}
}

func TestOffsetIgnoresRoundTrip(t *testing.T) {
	t1 := time.Unix(1788600000, 0)

	got, err := Offset(reply(t1, 200*time.Millisecond, 0), t1, t1.Add(400*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if got > Negligible || got < -Negligible {
		t.Fatalf("на исправных часах поправка %s — задержка канала посчитана как уход часов", got)
	}
}

func TestOffsetRejectsBadReplies(t *testing.T) {
	t1 := time.Unix(1788600000, 0)
	good := reply(t1, 10*time.Millisecond, 0)

	cases := map[string][]byte{
		"короткий ответ":            good[:20],
		"пустые метки":              func() []byte { b := make([]byte, PacketSize); b[0] = 4 << 3; b[0] |= 4; b[1] = 2; return b }(),
		"сервер не синхронизирован": func() []byte { b := append([]byte(nil), good...); b[0] |= 3 << 6; return b }(),
		"отказ в обслуживании":      func() []byte { b := append([]byte(nil), good...); b[1] = 0; return b }(),
		"не ответ сервера":          func() []byte { b := append([]byte(nil), good...); b[0] = 0<<6 | 4<<3 | 3; return b }(),
	}
	for name, resp := range cases {
		if _, err := Offset(resp, t1, t1.Add(20*time.Millisecond)); err == nil {
			t.Errorf("%s: ответ обязан быть отвергнут", name)
		}
	}
}

func TestRequestShape(t *testing.T) {
	r := Request()
	if len(r) != PacketSize {
		t.Fatalf("размер запроса %d", len(r))
	}
	if r[0]>>6 != 0 || (r[0]>>3)&7 != 4 || r[0]&7 != 3 {
		t.Fatalf("заголовок запроса собран неверно: %08b", r[0])
	}
}

func TestServersAreLiteralAddresses(t *testing.T) {
	if len(Servers) < 2 {
		t.Fatal("нужен запас серверов на случай недоступности одного")
	}
	for _, s := range Servers {
		for _, r := range s {
			if (r < '0' || r > '9') && r != '.' {
				t.Fatalf("адрес %q не числовой — при сломанных часах имя может не разрешиться", s)
			}
		}
	}
}
