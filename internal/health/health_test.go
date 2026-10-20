package health

import "testing"

func TestCatastrophicRegressionRollsBack(t *testing.T) {
	v := Judge([]Reading{{Name: "db-corrupt", BadNow: true, BadOnAnchor: false}})
	if v.Decision != Rollback {
		t.Fatalf("битая база после обновления должна вести к откату, получили %v", v.Decision)
	}
	if len(v.Reasons) == 0 {
		t.Error("вердикт отката обязан нести человеческую причину")
	}
}

func TestExternalCauseDoesNotRollBack(t *testing.T) {
	v := Judge([]Reading{{Name: "channel-offline", BadNow: true, BadOnAnchor: false}})
	if v.Decision != Healthy {
		t.Fatalf("падение провайдера не должно трогать версию, получили %v", v.Decision)
	}
}

func TestPreexistingBadIsNotRegression(t *testing.T) {
	v := Judge([]Reading{{Name: "intent-broken", BadNow: true, BadOnAnchor: true}})
	if v.Decision != Healthy {
		t.Fatalf("дефект, бывший и до обновления, не повод к откату, получили %v", v.Decision)
	}
}

func TestSoftRegressionAwaitsDecision(t *testing.T) {
	v := Judge([]Reading{{Name: "data-stuck", BadNow: true, BadOnAnchor: false}})
	if v.Decision != AwaitDecision {
		t.Fatalf("мягкая деградация должна ждать решения, получили %v", v.Decision)
	}
}

func TestCatastrophicOverridesSoft(t *testing.T) {
	v := Judge([]Reading{
		{Name: "data-stuck", BadNow: true, BadOnAnchor: false},
		{Name: "service-crash-loop", BadNow: true, BadOnAnchor: false},
	})
	if v.Decision != Rollback {
		t.Fatalf("при катастрофе рядом с мягкой деградацией — откат, получили %v", v.Decision)
	}
}

func TestAllGoodIsHealthy(t *testing.T) {
	v := Judge([]Reading{
		{Name: "db-corrupt", BadNow: false},
		{Name: "intent-broken", BadNow: false},
		{Name: "channel-offline", BadNow: false},
	})
	if v.Decision != Healthy {
		t.Fatalf("без регрессов версия здорова, получили %v", v.Decision)
	}
}

func TestUnknownCheckIgnored(t *testing.T) {
	v := Judge([]Reading{{Name: "signal-from-the-future", BadNow: true}})
	if v.Decision != Healthy {
		t.Fatalf("неизвестная проверка должна игнорироваться, получили %v", v.Decision)
	}
}

func TestRegistryIsCopy(t *testing.T) {
	r := Registry()
	if len(r) == 0 {
		t.Fatal("реестр проверок пуст")
	}
	r[0].Name = "подмена"
	if Registry()[0].Name == "подмена" {
		t.Error("Registry отдал ссылку на внутренний список, а не копию")
	}
}
