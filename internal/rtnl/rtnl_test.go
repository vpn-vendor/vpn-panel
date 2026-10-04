package rtnl

import (
	"encoding/hex"
	"os"
	"strings"
	"syscall"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/linkdump.hex")
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseDumpFixture(t *testing.T) {
	links, err := ParseDump(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(links) < 3 {
		t.Fatalf("карт %d", len(links))
	}
	seen := map[string]Link{}
	for _, l := range links {
		if l.Name == "" || l.Index <= 0 || !l.HasStats {
			t.Fatalf("карта без имени, номера или статистики: %+v", l)
		}
		seen[l.Name] = l
	}
	lo, ok := seen["lo"]
	if !ok || !lo.Up || lo.Index != 1 {
		t.Fatalf("петля: %+v %v", lo, ok)
	}
}

func TestWatcherOverflow(t *testing.T) {
	w := &Watcher{read: func(int, []byte) (int, error) { return 0, syscall.ENOBUFS }}
	ev, err := w.Next(make([]byte, 64<<10))
	if err != nil || len(ev) != 1 || ev[0].Kind != LinkOverflow {
		t.Fatalf("%v %v", ev, err)
	}
	w2 := &Watcher{read: func(int, []byte) (int, error) { return 0, syscall.EBADF }}
	if _, err := w2.Next(make([]byte, 64<<10)); err == nil {
		t.Fatal("закрытый сокет обязан дать ошибку")
	}
}

func TestParseEvents(t *testing.T) {
	ev, err := ParseEvents(fixture(t))
	if err != nil || len(ev) < 3 || ev[0].Kind != LinkChanged || ev[0].Name == "" {
		t.Fatalf("%v %v", ev, err)
	}
}

func TestLiveDumpAndWatchNoPrivileges(t *testing.T) {
	links, err := Dump()
	if err != nil || len(links) == 0 {
		t.Skipf("дамп недоступен здесь: %v", err)
	}
	w, err := Watch()
	if err != nil {
		t.Skipf("подписка недоступна здесь: %v", err)
	}
	_ = w.Close()
}
