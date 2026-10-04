package metrics

import (
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

func TestShutdownWaitsForSave(t *testing.T) {
	st := &mapStore{}
	src := fakeSource("s", time.Second, func() (map[string]float64, error) { return map[string]float64{"s.v": 1}, nil })
	c := New([]Source{src}, st, t.TempDir(), nil)
	c.record = func(models.AuthEvent) {}
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 30; i++ {
		c.Tick(base.Add(time.Duration(i) * time.Second))
	}
	r := NewRunner(c.dataDir, func() Roles { return Roles{} })
	go func() {
		defer close(r.done)
		_ = r.loop(c, NewLinkSource(func() Roles { return Roles{} }, nil))
	}()
	time.Sleep(50 * time.Millisecond)
	if err := r.Shutdown(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.dataDir, FileName)); err != nil {
		t.Fatal("после Shutdown файл не записан — процесс ушёл бы с недописанным файлом")
	}
	select {
	case <-r.done:
	default:
		t.Fatal("Shutdown вернулся раньше завершения цикла")
	}
}

func TestLoadRemovesStaleTemp(t *testing.T) {
	dir := t.TempDir()
	staged, err := durable.Stage(filepath.Join(dir, FileName), nil, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	c := New(nil, &mapStore{}, dir, nil)
	c.Load()
	if _, err := os.Stat(staged.Path()); err == nil {
		t.Fatal("временный файл остался")
	}
}
