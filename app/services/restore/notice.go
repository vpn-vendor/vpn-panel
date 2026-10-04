package restore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/app/services/backup"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

const SettingExported = "security.backup_exported"

const ExportNoticeFor = 7 * 24 * time.Hour

const fromConsole = "-"

const digestFresh = time.Minute

var digestCache struct {
	mu sync.Mutex
	at time.Time
	v  string
}

func (im *Importer) cachedDigest() (string, error) {
	digestCache.mu.Lock()
	defer digestCache.mu.Unlock()
	now := im.Now()
	if digestCache.v != "" && now.Sub(digestCache.at) >= 0 && now.Sub(digestCache.at) < digestFresh {
		return digestCache.v, nil
	}
	d, err := im.digest()
	if err != nil {
		return "", err
	}
	digestCache.at, digestCache.v = now, d
	return d, nil
}

type Notice struct {
	Level string
	Text  string
}

func (im *Importer) digest() (string, error) {
	doc, err := backup.Build(im.Entries, backupfile.KindCopy, "", time.Time{})
	if err != nil {
		return "", err
	}
	names := make([]string, 0, len(doc.Sections))
	for n := range doc.Sections {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00%s\x00", n, doc.Sections[n].Version, doc.Sections[n].Data)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (im *Importer) MarkExported(ip string) {
	d, err := im.digest()
	if err != nil {
		d = ""
	}
	if ip == "" {
		ip = fromConsole
	}
	digestCache.mu.Lock()
	digestCache.at, digestCache.v = im.Now(), d
	digestCache.mu.Unlock()
	_ = im.Store.Set(SettingExported, strconv.FormatInt(im.Now().Unix(), 10)+" "+ip+" "+d)
}

func (im *Importer) Notices() []Notice {
	f := strings.Fields(im.Store.Get(SettingExported))
	if len(f) < 2 {
		return []Notice{{Level: "info", Text: "Копии настроек ещё нет. Без неё забытый пароль диска означает настройку шлюза с нуля — выгрузите копию на странице «Резервная копия»."}}
	}
	var out []Notice
	sec, _ := strconv.ParseInt(f[0], 10, 64)
	at := time.Unix(sec, 0)
	if im.Now().Sub(at) < ExportNoticeFor {
		from := "с адреса " + f[1]
		if f[1] == fromConsole {
			from = "с консоли шлюза"
		}
		out = append(out, Notice{Level: "warn", Text: "Копия настроек со всеми ключами выгружена " + at.Local().Format("02.01.2006 в 15:04") +
			" " + from + ". Если это были не вы — отзовите чужие устройства на странице «Устройства» и попросите поставщика VPN выдать новые ключи."})
	}
	if len(f) > 2 {
		if d, err := im.cachedDigest(); err == nil && d != f[2] {
			out = append(out, Notice{Level: "info", Text: "Настройки изменились после последней копии — выгрузите новую на странице «Резервная копия»."})
		}
	}
	return out
}
