package takeover

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
)

const (
	bootA = "1b6a0c7e-0000-4000-8000-00000000000a"
	bootB = "1b6a0c7e-0000-4000-8000-00000000000b"
)

func standJournal(t *testing.T, ids ...string) (Journal, Env) {
	t.Helper()
	env := standEnv(t, standUnits)
	sel, err := Build(env).Select(ids)
	if err != nil {
		t.Fatal(err)
	}
	return Journal{Plan: sel, Stage: StageFinishing, Started: "2026-10-19T12:00:00Z"}, env
}

func TestJournalRoundTrip(t *testing.T) {
	j, _ := standJournal(t, "legacy.dhcp", "legacy.netplan", "legacy.tunnel")
	j.Before = map[string]UnitState{"openvpn@client1.service": on, "telegram_bot.service": etcFlap}
	j.Aside = []Aside{{Path: "/etc/netplan/99-vpn-script.yaml", Saved: "/var/lib/vpn-panel/takeover/1", Mode: 0o600}}
	j.Done = []Mark{{Key: "legacy.dhcp#0.disable.0123456789ab", Boot: bootA}}
	j.Failed = []string{"legacy.dhcp#2.stop.0123456789ab"}
	j.Backup = "/var/backups/vpn-panel/takeover-20261019T120000Z"
	j.Residue = []string{"netplan_backup", "resolved_header"}
	data, err := j.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseJournal(data)
	if err != nil {
		t.Fatal(err)
	}
	j.Schema = JournalSchema
	if !reflect.DeepEqual(got, j) {
		t.Fatalf("\nпрочитано %+v\nзаписано  %+v", got, j)
	}
}

func TestJournalRefuses(t *testing.T) {
	good, _ := standJournal(t, "legacy.dhcp")
	edit := func(f func(*Journal)) Journal {
		j := good
		j.Plan.Items = slices.Clone(good.Plan.Items)
		f(&j)
		return j
	}
	tests := []struct {
		name string
		j    Journal
		err  string
	}{
		{"незнакомый этап", edit(func(j *Journal) { j.Stage = "later" }), "этап"},
		{"без этапа", edit(func(j *Journal) { j.Stage = "" }), "этап"},
		{"без плана", edit(func(j *Journal) { j.Plan = Plan{} }), "без плана"},
		{"без отпечатка", edit(func(j *Journal) { j.Plan.Digest = "abc" }), "без плана"},
		{"запертый пункт", edit(func(j *Journal) { j.Plan.Items[0].Locked = true }), "заперт"},
		{"пункт дважды", edit(func(j *Journal) { j.Plan.Items = append(j.Plan.Items, j.Plan.Items[0]) }), "повторяется"},
		{"команда не из перечня", edit(func(j *Journal) {
			j.Plan.Items[0].Step3 = append(slices.Clone(j.Plan.Items[0].Step3), Op{Kind: OpExec, Command: "rm -rf /"})
		}), "перечне"},
		{"незнакомая операция", edit(func(j *Journal) {
			j.Plan.Items[0].Undo = []Op{{Kind: "reboot"}}
		}), "незнакомая"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.j.Marshal(); err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("записан: ошибка %v, ожидали с %q", err, tc.err)
			}

			tc.j.Schema = JournalSchema
			data := mustJSON(t, tc.j)
			if _, err := ParseJournal(data); err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("прочитан: ошибка %v, ожидали с %q", err, tc.err)
			}
		})
	}

	raw := []struct{ name, data, err string }{
		{"схема первого формата", `{"schema":1,"stage":"window"}`, "другой версии"},
		{"без схемы", `{"stage":"window"}`, "другой версии"},
		{"лишнее поле", strings.Replace(string(mustJSON(t, withSchema(good))), `"stage"`, `"extra":true,"stage"`, 1), "не читается"},
		{"не JSON", `schema=2`, "не читается"},
	}
	for _, tc := range raw {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseJournal([]byte(tc.data)); err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("ошибка %v, ожидали с %q", err, tc.err)
			}
		})
	}
	data, err := good.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJournal(data); err != nil {
		t.Fatalf("отрицательный контроль: годный журнал отвергнут: %v", err)
	}
	if _, err := withSchema(good, 1).Marshal(); err == nil {
		t.Error("журнал чужой схемы записан")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func withSchema(j Journal, s ...int) Journal {
	j.Schema = JournalSchema
	if len(s) > 0 {
		j.Schema = s[0]
	}
	return j
}

func TestJournalKeepsPlan(t *testing.T) {
	j, env := standJournal(t, "legacy.netplan", "legacy.pppoe", "legacy.tunnel")
	data, err := j.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(env.Root, legacyvpn.ScriptNetplan)); err != nil {
		t.Fatal(err)
	}
	stopped := standUnits.with("openvpn@client1.service", flaps).with("cron.service", flaps)
	env.Units = stopped.fn()
	again := Build(env)
	if again.Digest == j.Plan.Digest || slices.Contains(ids(again), "legacy.netplan") ||
		find(t, again, "legacy.tunnel").Undo != nil || hasOp(find(t, again, "legacy.pppoe").Undo, start("cron.service")) {
		t.Fatalf("отрицательный контроль: заново построенный план должен был потерять откат: %+v", again)
	}

	got, err := ParseJournal(data)
	if err != nil {
		t.Fatal(err)
	}
	var undo []Op
	for _, p := range got.Undo(got.Step1Boot) {
		undo = append(undo, p.Op)
	}
	if want := []Op{exec(CmdPon), start("cron.service"), start("openvpn@client1.service")}; !reflect.DeepEqual(undo, want) {
		t.Errorf("откат %+v\nожидали %+v", undo, want)
	}

	got.Step1Boot = bootA
	if after := got.Undo("другая-загрузка"); after != nil {
		t.Errorf("откат после перезагрузки запускает службы: %+v", after)
	}
	if same := got.Undo(bootA); len(same) != 3 {
		t.Errorf("откат в той же загрузке потерян: %+v", same)
	}
	if !slices.ContainsFunc(got.Pending(bootA), func(p PendingOp) bool { return reflect.DeepEqual(p.Op, backup(legacyvpn.ScriptNetplan)) }) {
		t.Errorf("шаг 3 потерял файл Netplan: %+v", got.Pending(bootA))
	}
	var step1 []Op
	for _, p := range got.Step1() {
		step1 = append(step1, p.Op)
	}
	if want := cat(find(t, j.Plan, "legacy.netplan").Step1, find(t, j.Plan, "legacy.pppoe").Step1, find(t, j.Plan, "legacy.tunnel").Step1); !reflect.DeepEqual(step1, want) {
		t.Errorf("шаг 1 %+v\nожидали %+v", step1, want)
	}
}

func TestPending(t *testing.T) {
	j, _ := standJournal(t, "legacy.script", "legacy.forward", "legacy.dhcp")
	all := j.Pending(bootA)
	n := 0
	for _, it := range j.Plan.Items {
		n += len(it.Step3)
	}
	if len(all) != n {
		t.Fatalf("несделанных %d, ожидали %d", len(all), n)
	}

	if all[0].ItemID != "legacy.dhcp" || all[len(all)-1].ItemID != "legacy.script" {
		t.Fatalf("порядок %+v", all)
	}
	j.Record(all[0].Key, bootA, nil)
	j.Record(all[1].Key, bootA, nil)
	if rest := j.Pending(bootA); len(rest) != len(all)-2 || !reflect.DeepEqual(rest[0], all[2]) {
		t.Fatalf("после частичного выполнения %+v", rest)
	}
	for _, p := range all {
		j.Record(p.Key, bootA, nil)
	}
	if left := j.Pending(bootA); len(left) != 0 {
		t.Fatalf("всё сделано, а осталось %+v", left)
	}
}

func pendingOps(ps []PendingOp, item string) []Op {
	var out []Op
	for _, p := range ps {
		if p.ItemID == item {
			out = append(out, p.Op)
		}
	}
	return out
}

func keyOf(t *testing.T, j Journal, item string, op Op) string {
	t.Helper()
	for _, it := range j.Plan.Items {
		if it.ID != item {
			continue
		}
		for i, o := range it.Step3 {
			if reflect.DeepEqual(o, op) {
				return OpKey(it.ID, i, o)
			}
		}
	}
	t.Fatalf("операции %+v нет в пункте %s", op, item)
	return ""
}

func TestPendingStopsOnFailure(t *testing.T) {
	drop := Op{Kind: OpDropLines, Path: legacyvpn.Crontab, Lines: []string{cronMinute, cronReboot}}
	tests := []struct {
		name      string
		fail      bool
		wantCron  bool
		wantOther bool
	}{
		{name: "правка crontab не удалась", fail: true, wantCron: false, wantOther: true},
		{name: "отрицательный контроль: без неудачи", fail: false, wantCron: true, wantOther: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			j, _ := standJournal(t, "legacy.pppoe", "legacy.dhcp")
			j.Record(keyOf(t, j, "legacy.pppoe", stop("cron.service")), bootA, nil)
			if tc.fail {
				j.Record(keyOf(t, j, "legacy.pppoe", drop), bootA, errors.New("нет места"))
			}
			p := j.Pending(bootA)
			pppoe := pendingOps(p, "legacy.pppoe")
			if hasOp(pppoe, start("cron.service")) != tc.wantCron {
				t.Errorf("запуск cron %v, ожидали %v: %+v", !tc.wantCron, tc.wantCron, pppoe)
			}
			if !reflect.DeepEqual(pppoe[0], drop) {
				t.Errorf("неудавшаяся операция не повторяется первой: %+v", pppoe)
			}
			if (len(pendingOps(p, "legacy.dhcp")) > 0) != tc.wantOther {
				t.Errorf("другой пункт встал вместе с неудачным: %+v", p)
			}
		})
	}

	j, _ := standJournal(t, "legacy.pppoe")
	k := keyOf(t, j, "legacy.pppoe", drop)
	j.Record(k, bootA, errors.New("нет места"))
	j.Record(k, bootA, nil)
	if len(j.Failed) != 0 || !hasOp(pendingOps(j.Pending(bootA), "legacy.pppoe"), start("cron.service")) {
		t.Errorf("удача не сняла неудачу: %+v", j)
	}
}

func TestPendingAfterReboot(t *testing.T) {
	j, _ := standJournal(t, "legacy.pppoe", "legacy.dhcp")
	pppoe := find(t, j.Plan, "legacy.pppoe").Step3

	for _, op := range pppoe[:2] {
		j.Record(keyOf(t, j, "legacy.pppoe", op), bootA, nil)
	}

	for _, p := range pendingOps(j.Pending(bootA), "legacy.dhcp") {
		j.Record(keyOf(t, j, "legacy.dhcp", p), bootA, nil)
	}
	tests := []struct {
		name string
		boot string
		want []Op
	}{
		{name: "та же загрузка", boot: bootA, want: pppoe[2:]},
		{name: "новая загрузка", boot: bootB, want: cat(pppoe[:1], pppoe[2:])},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := j.Pending(tc.boot)
			if got := pendingOps(p, "legacy.pppoe"); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("\nполучено %+v\nожидали  %+v", got, tc.want)
			}

			if got := pendingOps(p, "legacy.dhcp"); got != nil {
				t.Errorf("завершённый пункт снова в работе: %+v", got)
			}
		})
	}
}

func TestFinish(t *testing.T) {
	j, _ := standJournal(t, "legacy.pppoe", "legacy.dhcp")
	drop := Op{Kind: OpDropLines, Path: legacyvpn.Crontab, Lines: []string{cronMinute, cronReboot}}
	var ran []Op
	saves := 0
	failDrop := func(p PendingOp) error {
		ran = append(ran, p.Op)
		if reflect.DeepEqual(p.Op, drop) {
			return errors.New("нет места")
		}
		return nil
	}
	save := func(Journal) error { saves++; return nil }
	done, err := j.Finish(bootA, failDrop, save)
	if err != nil || done {
		t.Fatalf("проход: сделано %v, ошибка %v", done, err)
	}
	if hasOp(ran, start("cron.service")) || hasOp(ran, exec(CmdPoff)) {
		t.Errorf("после неудачи пункт пошёл дальше: %+v", ran)
	}
	if !hasOp(ran, mask("isc-dhcp-server.service")) {
		t.Errorf("другой пункт не сделан: %+v", ran)
	}
	if saves != len(ran) {
		t.Errorf("журнал записан %d раз на %d операций", saves, len(ran))
	}

	ran = nil
	done, err = j.Finish(bootA, func(p PendingOp) error { ran = append(ran, p.Op); return nil }, save)
	if err != nil || !done || !reflect.DeepEqual(ran[0], drop) || !hasOp(ran, start("cron.service")) || len(j.Failed) != 0 {
		t.Fatalf("второй проход: сделано %v, ошибка %v, операции %+v", done, err, ran)
	}

	j2, _ := standJournal(t, "legacy.dhcp")
	calls := 0
	_, err = j2.Finish(bootA, func(PendingOp) error { calls++; return nil }, func(Journal) error { return errors.New("диск") })
	if err == nil || calls != 1 {
		t.Fatalf("ошибка записи %v, операций %d", err, calls)
	}
}

func TestOpKey(t *testing.T) {
	op := Op{Kind: OpStop, Unit: "isc-dhcp-server.service"}
	k := OpKey("legacy.dhcp", 2, op)
	if k != OpKey("legacy.dhcp", 2, op) || !strings.HasPrefix(k, "legacy.dhcp#2.stop.") {
		t.Fatalf("ключ %q", k)
	}
	for _, other := range []string{
		OpKey("legacy.dhcp", 3, op),
		OpKey("foreign.dhcp.isc-dhcp-server", 2, op),
		OpKey("legacy.dhcp", 2, Op{Kind: OpStop, Unit: "dnsmasq.service"}),
	} {
		if other == k {
			t.Errorf("разные операции с одним ключом %q", k)
		}
	}
}
