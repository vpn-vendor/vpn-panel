package metrics

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/models"
)

type mapStore struct {
	mu sync.Mutex
	m  map[string]string
}

func (s *mapStore) Get(k string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k]
}
func (s *mapStore) Set(k, v string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]string{}
	}
	s.m[k] = v
	return nil
}

func fakeSource(name string, _ time.Duration, read func() (map[string]float64, error)) Source {
	return Source{Name: name, Title: name, Rows: []string{name + ".v"}, Persist: true, Read: read}
}

func newTest(t *testing.T, store *mapStore, srcs ...Source) *Collector {
	t.Helper()
	c := New(srcs, store, t.TempDir(), nil)
	c.record = func(models.AuthEvent) {}
	base := time.Unix(1_700_000_000, 0)
	c.now = func() time.Time { return base }
	return c
}

func TestConstantsFrozen(t *testing.T) {
	if Tick != time.Second || FuseStrikes != 3 || FusePauseMin != 5*time.Minute || FusePauseMax != time.Hour ||
		ProtectWindow != 10 || ProtectStale != 10*time.Second || SaveEvery != 5*time.Minute {
		t.Fatal("числа сборщика изменены")
	}

	if BudgetShare != 10 || AnomalyFactor != 10 || AnomalyFloor != time.Millisecond || BaselineSamples != 32 || BaselineMin != 8 {
		t.Fatal("форма предохранителя цены изменена")
	}
}

func TestFuseLimitSelfCalibrates(t *testing.T) {
	c := New(nil, &mapStore{}, "", nil)
	f := &fuse{}
	if c.limit(f) != Tick/BudgetShare {
		t.Fatalf("без базы порог обязан быть долей такта: %v", c.limit(f))
	}
	for i := 0; i < BaselineMin; i++ {
		f.sample(20 * time.Microsecond)
	}
	if c.limit(f) != AnomalyFloor {
		t.Fatalf("быстрая база: порог = пол, а не %v", c.limit(f))
	}
	for i := 0; i < BaselineSamples; i++ {
		f.sample(3 * time.Millisecond)
	}
	if c.limit(f) != 30*time.Millisecond {
		t.Fatalf("база 3 мс: порог 30 мс, а не %v", c.limit(f))
	}
	for i := 0; i < BaselineSamples; i++ {
		f.sample(50 * time.Millisecond)
	}
	if c.limit(f) != Tick/BudgetShare {
		t.Fatalf("медленная база не поднимает порог выше доли такта: %v", c.limit(f))
	}
}

func TestCombineIsAnd(t *testing.T) {
	now := time.Unix(1000, 0)
	on, off, mem := State{Mode: On}, State{Mode: Off}, State{Mode: Memory}
	p1 := State{Mode: Paused, Until: now.Add(time.Hour)}
	p2 := State{Mode: Paused, Until: now.Add(2 * time.Hour)}
	if Combine(on, on, now).Mode != On || Combine(off, on, now).Mode != Off || Combine(on, off, now).Mode != Off {
		t.Fatal("выключен обязан побеждать")
	}
	if got := Combine(p1, p2, now); got.Mode != Paused || !got.Until.Equal(p2.Until) {
		t.Fatalf("пауза до позднейшего срока: %+v", got)
	}
	if Combine(mem, on, now).Mode != Memory || Combine(on, mem, now).Mode != Memory {
		t.Fatal("только в памяти — если хоть у одного")
	}
	if Combine(p1, on, now.Add(3*time.Hour)).Mode != On {
		t.Fatal("истёкшая пауза = включён")
	}

	if Combine(on, p1, now).Mode != Paused {
		t.Fatal("рубильник «включить всё» — нарушение сценария 6")
	}
	for _, s := range []State{on, off, mem, p1} {
		if Parse(s.String()) != s {
			t.Fatalf("круг строка↔состояние: %+v → %q → %+v", s, s.String(), Parse(s.String()))
		}
	}
}

func TestSlowSourcePausesItself(t *testing.T) {
	st := &mapStore{}
	slow := fakeSource("slow", time.Millisecond, func() (map[string]float64, error) {
		time.Sleep(3 * time.Millisecond)
		return map[string]float64{"slow.v": 1}, nil
	})
	c := newTest(t, st, slow)
	c.tick = 10 * time.Millisecond
	base := c.now()
	for i := 0; i < 3; i++ {
		c.Tick(base.Add(time.Duration(i) * time.Second))
	}
	if got := Parse(st.Get(SettingSource + "slow")); got.Mode != Paused || !got.Until.Equal(base.Add(2*time.Second).Add(FusePauseMin)) {
		t.Fatalf("после трёх превышений: %+v", got)
	}
	if len(c.Notices()) != 1 || c.Reads("slow") != 3 {
		t.Fatalf("уведомлений %d, чтений %d", len(c.Notices()), c.Reads("slow"))
	}

	c.Tick(base.Add(10 * time.Second))
	if c.Reads("slow") != 3 {
		t.Fatal("источник на паузе читался")
	}

	trial := base.Add(2 * time.Second).Add(FusePauseMin).Add(time.Second)
	c.now = func() time.Time { return trial }
	c.Tick(trial)
	if c.Reads("slow") != 4 {
		t.Fatalf("пробная попытка не сделана: чтений %d", c.Reads("slow"))
	}
	if got := Parse(st.Get(SettingSource + "slow")); got.Mode != Paused || !got.Until.Equal(trial.Add(2*FusePauseMin)) {
		t.Fatalf("после провала пробы: %+v, ожидалась пауза до %v", got, trial.Add(2*FusePauseMin))
	}

	if err := c.SetSource("slow", State{Mode: On}, "127.0.0.1"); err != nil || len(c.Notices()) != 0 {
		t.Fatalf("возврат администратором: %v, уведомлений %d", err, len(c.Notices()))
	}
}

func TestErrorSourceSkipsSample(t *testing.T) {
	st := &mapStore{}
	fail := true
	bad := fakeSource("bad", time.Second, func() (map[string]float64, error) {
		if fail {
			return nil, errors.New("нет файла")
		}
		return map[string]float64{"bad.v": 5}, nil
	})
	good := fakeSource("good", time.Second, func() (map[string]float64, error) { return map[string]float64{"good.v": 7}, nil })
	c := newTest(t, st, bad, good)
	base := c.now()
	c.Tick(base)
	fail = false
	c.Tick(base.Add(time.Second))
	res := c.Query([]string{"bad.v", "good.v"}, base, base.Add(time.Second), 10)
	if len(res.Rows["good.v"]) != 2 || res.Rows["good.v"][0].Avg != 7 {
		t.Fatalf("сосед пострадал: %+v", res.Rows["good.v"])
	}
	if b := res.Rows["bad.v"]; len(b) != 2 || !math.IsNaN(b[0].Avg) || b[1].Avg != 5 {
		t.Fatalf("ошибка не стала пропуском: %+v", b)
	}
	if Parse(st.Get(SettingSource+"bad")).Mode != On {
		t.Fatal("одна ошибка не должна ставить на паузу")
	}
}

func TestMasterOffStopsReadsButNotProtection(t *testing.T) {
	st := &mapStore{}
	_ = st.Set(SettingMaster, "off")
	src := fakeSource("s", time.Second, func() (map[string]float64, error) { return map[string]float64{"s.v": 1}, nil })
	c := newTest(t, st, src)
	if c.Protection().OK {
		t.Fatal("без данных датчики обязаны сказать «нет данных»")
	}
	base := c.now()
	for i := 0; i < 3; i++ {
		now := base.Add(time.Duration(i) * time.Second)
		c.now = func() time.Time { return now }
		c.Tick(now)
		time.Sleep(40 * time.Millisecond)
	}
	if c.Reads("s") != 0 {
		t.Fatalf("при выключенном рубильнике источник читался %d раз", c.Reads("s"))
	}
	if _, err := os.Stat("/proc/stat"); err == nil && !c.Protection().OK {
		t.Fatal("датчики защиты выключились вместе с рубильником")
	}
	if len(c.Notices()) == 0 {
		t.Fatal("«выключен насовсем» без уведомления наверху страниц")
	}

	if err := c.SetMaster(State{Mode: On}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	c.Tick(base.Add(5 * time.Second))
	if c.Reads("s") != 1 {
		t.Fatal("после включения рубильника источник не читается")
	}
}

func TestReadersDoNotTriggerReads(t *testing.T) {
	st := &mapStore{}
	src := fakeSource("s", time.Second, func() (map[string]float64, error) { return map[string]float64{"s.v": 1}, nil })
	c := newTest(t, st, src)
	base := c.now()
	c.Tick(base)
	before := c.Reads("s")
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Query([]string{"s.v"}, base.Add(-time.Hour), base, 500)
		}()
	}
	wg.Wait()
	if c.Reads("s") != before {
		t.Fatal("читатели вызвали чтение источника")
	}
}

func TestSaveRespectsMemoryOnlyAndFixedSize(t *testing.T) {
	st := &mapStore{}
	src := fakeSource("s", time.Second, func() (map[string]float64, error) { return map[string]float64{"s.v": 1}, nil })
	c := newTest(t, st, src)
	base := c.now()
	for i := 0; i < 100; i++ {
		c.Tick(base.Add(time.Duration(i) * time.Second))
	}
	_ = st.Set(SettingMaster, "memory")
	c.mu.Lock()
	c.refreshStates(base, true)
	c.mu.Unlock()
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(c.dataDir, FileName)); err == nil {
		t.Fatal("«только в памяти» — а файл записан")
	}
	_ = st.Set(SettingMaster, "on")
	c.mu.Lock()
	c.refreshStates(base, true)
	c.mu.Unlock()
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(c.dataDir, FileName))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("файл после сохранения: %v %v", fi, err)
	}
	size := fi.Size()
	for i := 100; i < 20_000; i++ {
		c.Tick(base.Add(time.Duration(i) * time.Second))
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	fi2, _ := os.Stat(filepath.Join(c.dataDir, FileName))
	if fi2.Size() != size {
		t.Fatalf("файл вырос: %d → %d", size, fi2.Size())
	}

	if m, _ := filepath.Glob(filepath.Join(c.dataDir, FileName+".*")); len(m) != 0 {
		t.Fatalf("остались временные файлы: %v", m)
	}

	c2 := New([]Source{src}, st, c.dataDir, nil)
	c2.Load()
	if c2.rows["s.v"].Last().IsZero() == false {
		t.Fatal("уровень 0 прочитан с диска, а не должен")
	}
	res := c2.Query([]string{"s.v"}, base, base.Add(20_000*time.Second), 100)
	if len(res.Rows["s.v"]) == 0 {
		t.Fatal("история после чтения пуста")
	}
}
