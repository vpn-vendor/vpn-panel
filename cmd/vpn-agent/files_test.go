package main

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
)

var written = map[string]string{
	"vpnStateFile":           vpnStateFile,
	"watchdogMemoryFile":     watchdogMemoryFile,
	"lockdownFile":           lockdownFile,
	"nftFile":                nftFile,
	"sysctlFile":             sysctlFile,
	"qosStateFile":           qosStateFile,
	"checkpointFile":         checkpointFile,
	"supportKeyFile":         supportKeyFile,
	"diskChangeRequest":      diskChangeRequest,
	"diskChangeLast":         diskChangeLast,
	"netplanFile":            netplanFile,
	"netplanBackup":          netplanBackup,
	"keaConfigFile":          keaConfigFile,
	"keaDropInFile":          keaDropInFile,
	"unboundFile":            unboundFile,
	"resolvedDropIn":         resolvedDropIn,
	"pppoePeerPath":          pppoePeerPath,
	"nmConnFile":             nmConnFile,
	"nmDropInFile":           nmDropInFile,
	"linkLocalNMFile":        linkLocalNMFile,
	"linklocal.go: dropIn":   linkLocalNetworkdDir + "/10-netplan-ens4.network.d/" + linkLocalDropInName,
	"linklocal.go: path":     linkLocalNetworkdDir + "/" + linkLocalOwnPrefix + "ens4.network",
	"updatesConfPath":        updatesConfPath,
	"updatesPauseConfPath":   updatesPauseConfPath,
	"updatesChoiceFile":      updatesChoiceFile,
	"aptSourcePath":          aptSourcePath,
	"policyStatePath":        policyStatePath,
	"releaseGoodFile":        releaseGoodFile,
	"probationFile":          probationFile,
	"hostCacheFile":          hostCacheFile,
	"rollbackIntentFile":     rollbackIntentFile,
	"rollbackOutcomeFile":    rollbackOutcomeFile,
	"panelDBPath":            panelDBPath,
	"panelDBPath + \"-wal\"": panelDBPath + "-wal",
	"panelDBPath + \"-shm\"": panelDBPath + "-shm",
	"probation.go: dst":      heldDebDir + "/vpn-panel_0.3.3.deb",
	"tempKeyPath":            tempKeyPath,
	"tempKeyConf":            tempKeyConf,
	"livePath()":             livePath(),
	"ovpnLivePath()":         ovpnLivePath(),

	"compose.go: c.path":                   netFactsFile,
	"support.go: p":                        supportDir + "/" + supportPrefix + "20261003-120000.txt",
	"support.go: path":                     supportDir + "/" + supportPrefix + "20261003-120000.txt.gz",
	"vpn_wg.go: path":                      wgDir + "/" + wgProfilePfx + "office.conf",
	"vpn_ovpn.go: path":                    ovpnDir + "/" + ovpnProfilePfx + "office.conf",
	"updates.go: path":                     updatesConfPath,
	"pppoe.go: path":                       pppoeChapSecret,
	"pppoe.go: f.path":                     pppoePapSecret,
	"pppoe.go: f.path + pppoeBackupSuffix": pppoeChapSecret + pppoeBackupSuffix,
	"pppoeFailFile":                        pppoeFailFile,

	"takeover.go: journal":    takeoverJournalFile,
	"takeover.go: saved":      takeoverAsideDir + "/x",
	"takeover_exec.go: saved": takeoverAsideDir + "/x",
}

var foreignWritten = map[string]string{
	"takeover.go: path":          "возврат на место файла, ушедшего в сторону на время окна: чужой файл Netplan",
	"takeover_exec.go: path":     "чужой файл по плану журнала: уходит в сторону или в копию, правится построчно (crontab, sudoers, sysctl, юниты, Netplan, udev, сценарии)",
	"takeover_exec.go: src":      "удаление чужого файла после копии: оригинал или его копия в стороне",
	"takeover_exec.go: dup":      "резервная копия старого шлюза: остаётся навсегда, удаление пакета её не трогает намеренно",
	"takeover_exec.go: manifest": "опись резервной копии старого шлюза рядом с файлами",
	"takeover_home.go: dup":      "копия vpn.sh в резервной копии старого шлюза",
	"takeover_home.go: path":     "заглушка на месте vpn.sh в домашнем каталоге",
}

func TestEveryWrittenFileIsInRegistry(t *testing.T) {
	seen := map[string]bool{}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "durable" {
				return true
			}
			switch sel.Sel.Name {
			case "Write", "WriteIfChanged", "Stage", "Remove":
			default:
				return true
			}
			var b strings.Builder
			_ = printer.Fprint(&b, fset, call.Args[0])
			expr := b.String()
			key := expr
			if _, ok := written[key]; !ok {
				key = name + ": " + expr
			}
			_, own := written[key]
			_, foreign := foreignWritten[key]
			if !own && !foreign {
				t.Errorf("%s: надёжная запись по пути %q не описана — добавьте файл в реестр и в таблицу теста", name, expr)
				return true
			}
			seen[key] = true
			return true
		})
	}
	var stale []string
	for key, sample := range written {
		if !seen[key] {
			stale = append(stale, key)
		}
		if !managed(sample) {
			t.Errorf("путь %s (%s) не в реестре файлов службы", sample, key)
		}
	}
	for key, reason := range foreignWritten {
		if !seen[key] {
			stale = append(stale, key)
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("запись в чужой файл %s без причины", key)
		}
		if _, dup := written[key]; dup {
			t.Errorf("%s и в своих, и в чужих записях", key)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("строки таблицы без записи в коде — убрать: %v", stale)
	}
}

func TestRegistryIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range managedFiles {
		if seen[f.Path] {
			t.Errorf("%s в реестре дважды", f.Path)
		}
		seen[f.Path] = true

		if !filepath.IsAbs(f.Path) || (strings.Contains(filepath.Dir(f.Path), "*") && !strings.HasPrefix(f.Path, "/run/")) {
			t.Errorf("%s: нужен полный путь, «*» — только в имени файла", f.Path)
		}
		if durable.IsTemp(filepath.Base(f.Path)) {
			t.Errorf("%s: имя совпадает с временным файлом надёжной записи", f.Path)
		}
	}
}

func TestPurgeCoversRegistry(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "debian", "postrm"))
	if err != nil {
		t.Fatal(err)
	}
	postrm := string(raw)
	wholesale := func(path string) bool {
		for dir := filepath.Dir(path); dir != "/" && dir != "/etc"; dir = filepath.Dir(dir) {
			if strings.Contains(postrm, "rm -rf "+dir+"\n") || strings.Contains(postrm, "rm -rf "+dir+" ") {
				return true
			}
		}
		return false
	}
	for _, f := range managedFiles {
		if f.Keep != "" {
			continue
		}
		if !strings.Contains(postrm, f.Path) && !wholesale(f.Path) {
			t.Errorf("удаление пакета не убирает %s", f.Path)
		}
	}
	for _, dir := range managedDirs() {
		if !strings.Contains(postrm, " "+dir+" ") && !strings.Contains(postrm, " "+dir+";") && !wholesale(dir+"/x") {
			t.Errorf("удаление пакета не убирает недописанные файлы в %s", dir)
		}
	}
}
