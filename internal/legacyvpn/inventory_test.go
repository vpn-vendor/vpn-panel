package legacyvpn

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestPPPoECronLines(t *testing.T) {
	const reboot = "@reboot root sleep 20 && /usr/bin/pon dsl-provider"
	const minute = "* * * * * root pgrep -f 'pppd call dsl-provider' > /dev/null || /usr/bin/pon dsl-provider"
	tests := []struct {
		name, crontab string
		want          []string
	}{
		{"строки скрипта с пробелами по краям и повтором",
			crontabStock + "  " + reboot + "\r\n" + minute + "\n" + minute + "\n", []string{reboot, minute}},
		{"закомментировано и чужой пир", "#" + reboot + "\n@reboot root /usr/bin/pon office\n0 3 * * * root /usr/bin/poff dsl-provider\n", nil},
		{"чистый crontab", crontabStock, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PPPoECronLines([]byte(tc.crontab)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("получено %q, ожидали %q", got, tc.want)
			}
		})
	}
}

func TestSudoersLinesMatchStand(t *testing.T) {
	root := false
	for _, l := range SudoersLines() {
		if !strings.Contains(sudoersScript, l+"\n") {
			t.Errorf("строки %q нет в файле фикстуры", l)
		}
		root = root || grantsRoot(l)
	}
	if !root {
		t.Error("ни одна строка не даёт root")
	}
}

func TestInventoryCoversDetect(t *testing.T) {
	var units []string
	for _, tu := range Tunnels() {
		units = append(units, tu.Unit)
	}
	if !reflect.DeepEqual(units, tunnelUnits) {
		t.Errorf("каналы %v, опись смотрит %v", units, tunnelUnits)
	}
	ds := Daemons()
	if len(ds) != len(ownUnits) {
		t.Fatalf("служб %d, в описи %d", len(ds), len(ownUnits))
	}
	scripts := 0
	for _, d := range ds {
		if !slices.ContainsFunc(ownUnits, func(u struct{ name, prog string }) bool { return u.name == d.Name }) {
			t.Errorf("службы %s нет в описи", d.Name)
		}
		if d.Script != "" {
			scripts++
		}
	}

	if scripts != len(ownScripts)-1 {
		t.Errorf("сценариев служб %d", scripts)
	}

	for dir, conf := range map[string]string{OpenVPNDir: OpenVPNConf, WireGuardDir: WireGuardConf} {
		if filepath.Dir(conf) != dir {
			t.Errorf("файл %s не в каталоге %s", conf, dir)
		}
	}
}
