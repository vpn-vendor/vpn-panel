package main

import (
	"log"
	"path/filepath"
	"sort"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
)

type managedFile struct {
	Path string
	Keep string
}

var managedFiles = []managedFile{
	{Path: vpnStateFile},
	{Path: netFactsFile},
	{Path: lockdownFile},
	{Path: qosStateFile},
	{Path: checkpointFile},
	{Path: supportKeyFile},
	{Path: supportDir + "/" + supportPrefix + "*", Keep: "файл в памяти: каталог службы исчезает вместе с ней"},
	{Path: diskChangeRequest},
	{Path: diskChangeLast},
	{Path: watchdogMemoryFile},
	{Path: netplanFile, Keep: "сеть клиента после удаления пакета не трогается"},
	{Path: netplanBackup},
	{Path: nftFile},
	{Path: sysctlFile},
	{Path: keaConfigFile},
	{Path: keaDropInFile},
	{Path: unboundFile},
	{Path: resolvedDropIn},
	{Path: pppoePeerPath},
	{Path: pppoePeerPath + pppoeBackupSuffix},
	{Path: pppoeChapSecret, Keep: "общий файл системы: при удалении снимается только своя строка"},
	{Path: pppoeChapSecret + pppoeBackupSuffix},
	{Path: pppoePapSecret, Keep: "общий файл системы: при удалении снимается только своя строка"},
	{Path: pppoePapSecret + pppoeBackupSuffix},
	{Path: wgDir + "/" + wgProfilePfx + "*.conf"},
	{Path: livePath()},
	{Path: ovpnDir + "/" + ovpnProfilePfx + "*.conf"},
	{Path: ovpnLivePath()},
	{Path: nmDropInFile},
	{Path: nmConnFile},
	{Path: linkLocalNMFile},
	{Path: linkLocalNetworkdDir + "/10-netplan-*.network.d/" + linkLocalDropInName},
	{Path: linkLocalNetworkdDir + "/" + linkLocalOwnPrefix + "*.network"},
	{Path: updatesConfPath},
	{Path: tempKeyPath, Keep: "ключ первой загрузки: снимается шагом первой загрузки, до него без ключа диск не откроется"},
	{Path: tempKeyConf, Keep: "настройка первой загрузки: снимается вместе с ключом"},
}

func managedDirs() []string {
	seen := map[string]bool{}
	var dirs []string
	for _, f := range managedFiles {
		d := filepath.Dir(f.Path)
		found := []string{d}
		if strings.Contains(d, "*") {
			found, _ = filepath.Glob(d)
		}
		for _, d := range found {
			if !seen[d] {
				seen[d] = true
				dirs = append(dirs, d)
			}
		}
	}
	sort.Strings(dirs)
	return dirs
}

func managed(path string) bool {
	for _, f := range managedFiles {
		if ok, err := filepath.Match(f.Path, path); err == nil && ok {
			return true
		}
	}
	return false
}

func sweepLeftovers() {
	for _, dir := range managedDirs() {
		n, err := durable.Sweep(dir)
		if err != nil {
			log.Printf("files: leftovers in %s not removed: %v", dir, err)
			continue
		}
		if n > 0 {
			log.Printf("files: removed %d unfinished file(s) in %s", n, dir)
		}
	}
}
