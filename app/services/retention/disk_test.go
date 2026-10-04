package retention

import "testing"

func TestBudgetFormula(t *testing.T) {
	const S = 40 * GiB

	ceiling, budget, starved := Budget(S, 25*GiB, 20*MiB, 0)
	if ceiling != 4*GiB || budget != 2*GiB || starved {
		t.Fatalf("обычный диск: потолок %d, бюджет %d, нехватка %v", ceiling, budget, starved)
	}

	if _, b, _ := Budget(S, 25*GiB, 20*MiB, 3*GiB); b != 3*GiB {
		t.Fatalf("3 ГиБ в потолке: %d", b)
	}

	if _, b, _ := Budget(S, 25*GiB, 20*MiB, 8*GiB); b != 4*GiB {
		t.Fatalf("прижим к потолку: %d", b)
	}

	if c, b, st := Budget(S, 3*GiB, 20*MiB, 0); c != 0 || b != BudgetFloor || !st {
		t.Fatalf("заполненный диск: потолок %d, бюджет %d, нехватка %v", c, b, st)
	}

	c1, _, _ := Budget(S, 22*GiB, 3*GiB, 0)
	c2, _, _ := Budget(S, 25*GiB, 0, 0)
	if c1 != c2 {
		t.Fatalf("потолок зависит от того, где лежат байты: %d против %d", c1, c2)
	}

	if c, _, _ := Budget(2048*GiB, 1000*GiB, 0, 0); c != CeilingHard {
		t.Fatalf("жёсткий верх: %d", c)
	}

	if _, b, st := Budget(8*GiB, 5*GiB, 0, 0); b != 8*GiB/10 || st {
		t.Fatalf("маленький диск: %d %v", b, st)
	}
}

func TestPressureThresholds(t *testing.T) {
	const S = 40 * GiB
	if Pressure(S, 25*GiB) != 0 || Pressure(S, 3*GiB) != 1 || Pressure(S, 1*GiB) != 2 {
		t.Fatal("пороги 10 % / 5 % на 40 ГиБ")
	}

	if Pressure(4*GiB, 900*MiB) != 1 || Pressure(4*GiB, 400*MiB) != 2 {
		t.Fatal("абсолютные минимумы порогов")
	}
}

func TestHysteresisRaisesOnlyAfterTwoChecks(t *testing.T) {
	diskMu.Lock()
	ceilingActing, ceilingSeen = 0, 0
	diskMu.Unlock()
	if got := applyHysteresis(4 * GiB); got != 4*GiB {
		t.Fatalf("первое значение принимается: %d", got)
	}
	if got := applyHysteresis(2 * GiB); got != 2*GiB {
		t.Fatalf("понижение сразу: %d", got)
	}
	if got := applyHysteresis(4 * GiB); got != 2*GiB {
		t.Fatalf("первый рост не применяется: %d", got)
	}
	if got := applyHysteresis(4 * GiB); got != 4*GiB {
		t.Fatalf("второй рост подряд применяется: %d", got)
	}
	if got := applyHysteresis(4*GiB + 100*MiB); got != 4*GiB {
		t.Fatalf("рост меньше 10 %% не двигает потолок: %d", got)
	}
}

func TestApprovedDiskNumbers(t *testing.T) {
	if ReservePercent != 15 || ReserveMin != 2*GiB || CeilingPercent != 10 || CeilingHard != 10*GiB ||
		BudgetDefault != 2*GiB || BudgetFloor != 256*MiB || WarnPercent != 10 || CriticalPercent != 5 ||
		SyslogCap != 256*MiB {
		t.Fatal("числа бюджета и сторожа диска утверждены владельцем — менять только решением")
	}
	if len(SyslogFiles) != 6 {
		t.Fatal("список системных журналов — ровно шесть файлов правила ротации rsyslog")
	}
}
