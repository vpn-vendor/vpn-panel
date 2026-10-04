package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupcode"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupcrypt"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
	"github.com/vpn-vendor/vpn-panel-core/internal/diskpass"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

const (
	codeBackupNoCode    = 2101
	codeBackupWrongCode = 2102
	codeBackupWeak      = 2103
	codeBackupTooMany   = 2104
	codeBackupPassword  = 2105
	codeBackupFile      = 2106
	codeBackupTooLarge  = 2107
	codeBackupApply     = 2108
)

const secretsVersion = 2

type backupSecrets struct {
	Version  int               `json:"version"`
	Profiles []secretProfile   `json:"profiles,omitempty"`
	PPPoE    *pppoeCredentials `json:"pppoe,omitempty"`
}

type secretProfile struct {
	Protocol vpndriver.Protocol `json:"protocol"`
	Slug     string             `json:"slug"`
	Text     string             `json:"text"`
}

type profileRef struct {
	Protocol vpndriver.Protocol `json:"protocol"`
	Slug     string             `json:"slug"`
}

func (s backupSecrets) find(r profileRef) (secretProfile, bool) {
	for _, p := range s.Profiles {
		if p.Protocol == r.Protocol && p.Slug == r.Slug {
			return p, true
		}
	}
	return secretProfile{}, false
}

type pppoeCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type secretsInventory struct {
	Profiles []profileRef `json:"profiles"`
	PPPoE    bool         `json:"pppoe"`
}

func (s backupSecrets) inventory() secretsInventory {
	refs := make([]profileRef, 0, len(s.Profiles))
	for _, p := range s.Profiles {
		refs = append(refs, profileRef{Protocol: p.Protocol, Slug: p.Slug})
	}
	return secretsInventory{Profiles: refs, PPPoE: s.PPPoE != nil}
}

type restoreChoice struct {
	Profiles []profileRef `json:"profiles"`
	PPPoE    bool         `json:"pppoe"`
}

type backupApplier struct {
	codes *backupcode.Store

	limiter *ratelimit.Limiter

	policyOnce sync.Once
	policy     *diskpass.Policy
	policyErr  error

	collect func() (backupSecrets, error)
	restore func(backupSecrets, restoreChoice) (map[string]any, *agentrpc.ErrorObject)
	prune   func(backupSecrets) (map[string]any, *agentrpc.ErrorObject)
}

func newBackupApplier(v *vpnApplier) *backupApplier {
	return &backupApplier{
		codes:   backupcode.New(),
		limiter: ratelimit.New(6, 1, time.Minute),
		collect: v.collectSecrets,
		restore: v.restoreSecrets,
		prune:   v.pruneSecrets,
	}
}

func backupErr(code int, msg string) *agentrpc.ErrorObject {
	return &agentrpc.ErrorObject{Code: code, Message: msg, Data: map[string]any{"recoverable": true}}
}

func (b *backupApplier) backupCode(json.RawMessage) (any, *agentrpc.ErrorObject) {
	code, err := b.codes.Issue()
	if err != nil {
		return nil, detailErr("не удалось выдать код — повторите", err.Error(), true)
	}
	log.Printf("backup: выдан код выгрузки копии")
	return map[string]any{"code": code, "expires_in_sec": int(backupcode.TTL / time.Second)}, nil
}

type backupExportParams struct {
	Code     string          `json:"code"`
	Password string          `json:"password"`
	Document json.RawMessage `json:"document"`
}

func (b *backupApplier) backupExport(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p backupExportParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, invalidParams()
	}
	if !b.limiter.Allow("export") {
		return nil, agentrpc.Busy(codeBackupTooMany, "копия запрашивается слишком часто — подождите минуту", b.limiter.RetryIn("export"))
	}

	if aerr := b.checkPassword(p.Password); aerr != nil {
		return nil, aerr
	}
	doc, err := backupfile.Parse(p.Document)
	if err != nil {
		return nil, backupErr(codeBackupFile, err.Error())
	}
	if doc.Kind != backupfile.KindCopy || len(doc.Secrets) > 0 {
		return nil, backupErr(codeBackupFile, "секреты в копию кладёт только агент — обновите страницу и повторите")
	}
	if err := b.codes.Use(p.Code); err != nil {
		if errors.Is(err, backupcode.ErrWrongCode) {
			return nil, backupErr(codeBackupWrongCode, err.Error())
		}
		return nil, backupErr(codeBackupNoCode, err.Error())
	}
	sec, err := b.collect()
	if err != nil {
		return nil, detailErr("не удалось прочитать ключи подключений — повторите", err.Error(), true)
	}
	if doc.Secrets, err = json.Marshal(sec); err != nil {
		return nil, detailErr("не удалось собрать копию — повторите", err.Error(), true)
	}
	plain, err := backupfile.Marshal(doc)
	if err != nil {
		return nil, detailErr("не удалось собрать копию — повторите", err.Error(), true)
	}
	if len(plain) > backupfile.MaxBytes {
		return nil, backupErr(codeBackupTooLarge, "копия получилась больше допустимого — удалите лишние профили подключений и повторите")
	}
	cipher, err := backupcrypt.Encrypt(plain, p.Password)
	if err != nil {
		return nil, detailErr("не удалось зашифровать копию — повторите", err.Error(), true)
	}
	inv := sec.inventory()
	log.Printf("backup: копия выгружена (профилей: %d, PPPoE: %v)", len(inv.Profiles), inv.PPPoE)
	return map[string]any{"file": base64.StdEncoding.EncodeToString(cipher), "secrets": inv}, nil
}

func (b *backupApplier) checkPassword(pw string) *agentrpc.ErrorObject {
	b.policyOnce.Do(func() {
		host, _ := os.Hostname()
		b.policy, b.policyErr = diskpass.Builtin(host)
	})
	if b.policyErr != nil {
		return detailErr("не удалось проверить пароль — повторите", b.policyErr.Error(), true)
	}
	if r := b.policy.Check(pw); r != diskpass.OK {
		return &agentrpc.ErrorObject{Code: codeBackupWeak, Message: passwordAdvice(r),
			Data: map[string]any{"recoverable": true, "reason": string(r)}}
	}
	return nil
}

func passwordAdvice(r diskpass.Reason) string {
	switch r {
	case diskpass.NotLatin:
		return "в пароле копии только латинские буквы, цифры и знаки — так его можно набрать на любой клавиатуре"
	case diskpass.Short:
		return fmt.Sprintf("пароль копии — не короче %d символов: длина защищает копию, если файл попадёт в чужие руки", diskpass.MinLength)
	case diskpass.Trivial:
		return "это простая последовательность или повтор — такой пароль подбирают первым; придумайте другой"
	case diskpass.Common:
		return "этот пароль есть в списках частых паролей — придумайте другой"
	case diskpass.Context:
		return "в пароле есть имя этого шлюза — его знает каждый, кто видит сеть; придумайте другой"
	}
	return "пароль копии не подходит — придумайте другой"
}

type backupFileParams struct {
	Password string        `json:"password"`
	File     string        `json:"file"`
	Restore  restoreChoice `json:"restore"`
}

func (b *backupApplier) openCopy(raw json.RawMessage) (*backupfile.Document, backupSecrets, restoreChoice, *agentrpc.ErrorObject) {
	var p backupFileParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, backupSecrets{}, restoreChoice{}, invalidParams()
	}

	if !b.limiter.Ready("open") {
		return nil, backupSecrets{}, restoreChoice{}, agentrpc.Busy(codeBackupTooMany, "слишком много неверных паролей подряд — подождите минуту", b.limiter.RetryIn("open"))
	}
	cipher, err := base64.StdEncoding.DecodeString(p.File)
	if err != nil {
		return nil, backupSecrets{}, restoreChoice{}, backupErr(codeBackupFile, "это не файл копии настроек панели")
	}
	plain, err := backupcrypt.Decrypt(cipher, p.Password, backupfile.MaxBytes)
	switch {
	case errors.Is(err, backupcrypt.ErrTooLarge):
		return nil, backupSecrets{}, restoreChoice{}, backupErr(codeBackupTooLarge, err.Error())
	case err != nil:
		b.limiter.Charge("open")
		return nil, backupSecrets{}, restoreChoice{}, backupErr(codeBackupPassword, backupcrypt.ErrWrongPassword.Error())
	}
	doc, err := backupfile.Parse(plain)
	if err != nil {
		return nil, backupSecrets{}, restoreChoice{}, backupErr(codeBackupFile, err.Error())
	}
	if doc.Kind != backupfile.KindCopy {
		return nil, backupSecrets{}, restoreChoice{}, backupErr(codeBackupFile, "это шаблон, а не копия — откройте его как шаблон")
	}
	sec, err := parseSecrets(doc.Secrets)
	if err != nil {
		return nil, backupSecrets{}, restoreChoice{}, backupErr(codeBackupFile, err.Error())
	}
	doc.Secrets = nil
	return doc, sec, p.Restore, nil
}

func parseSecrets(raw json.RawMessage) (backupSecrets, error) {
	var s backupSecrets
	if len(raw) == 0 {
		return backupSecrets{Version: secretsVersion}, nil
	}
	var head struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return s, backupfile.ErrMalformed
	}
	switch {
	case head.Version > secretsVersion:
		return s, backupfile.ErrNewer
	case head.Version < 1:
		return s, backupfile.ErrMalformed
	case head.Version == 1:
		v, err := fromV1(raw)
		if err != nil {
			return s, err
		}
		s = v
	default:
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&s); err != nil {
			return s, backupfile.ErrMalformed
		}
	}

	seen := map[string]bool{}
	for _, p := range s.Profiles {
		if p.Protocol == "" || !vpndriver.ValidSlug(p.Slug) || seen[p.Slug] {
			return s, backupfile.ErrMalformed
		}
		seen[p.Slug] = true
	}
	if s.PPPoE != nil && (!validPPPoEUser(s.PPPoE.Username) || !validPPPoESecret(s.PPPoE.Password)) {
		return s, backupfile.ErrMalformed
	}
	return s, nil
}

func (b *backupApplier) backupOpen(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	doc, sec, _, aerr := b.openCopy(raw)
	if aerr != nil {
		return nil, aerr
	}
	return map[string]any{"document": doc, "secrets": sec.inventory()}, nil
}

func (b *backupApplier) backupApplySecrets(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	_, sec, choice, aerr := b.openCopy(raw)
	if aerr != nil {
		return nil, aerr
	}
	for _, r := range choice.Profiles {
		if _, ok := sec.find(r); !ok {
			return nil, backupErr(codeBackupApply, "в копии нет выбранного профиля — обновите страницу")
		}
	}
	if choice.PPPoE && sec.PPPoE == nil {
		return nil, backupErr(codeBackupApply, "в копии нет пароля PPPoE — обновите страницу")
	}
	return b.restore(sec, choice)
}

func (v *vpnApplier) collectSecrets() (backupSecrets, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	sec := backupSecrets{Version: secretsVersion}
	for proto, drv := range v.drivers {
		for _, slug := range drv.listProfiles() {
			text, err := drv.profileText(slug)
			if err != nil {
				return sec, fmt.Errorf("профиль %s: %w", slug, err)
			}
			sec.Profiles = append(sec.Profiles, secretProfile{Protocol: proto, Slug: slug, Text: text})
		}
	}
	sortProfiles(sec.Profiles)

	if !pppoeInUse() {
		return sec, nil
	}
	creds, err := readPPPoE()
	if err != nil {
		return sec, err
	}
	sec.PPPoE = creds
	return sec, nil
}

var (
	pppoeInUse = pppoeUnitEnabled
	readPPPoE  = readPPPoECredentials
)

func (v *vpnApplier) restoreSecrets(sec backupSecrets, choice restoreChoice) (map[string]any, *agentrpc.ErrorObject) {
	v.mu.Lock()
	defer v.mu.Unlock()
	warnings := map[string][]string{}
	for _, r := range choice.Profiles {
		p, _ := sec.find(r)
		drv, ok := v.drivers[p.Protocol]
		if !ok {
			return nil, backupErr(codeBackupApply, "протокол подключения «"+p.Slug+"» эта версия не поддерживает — обновите панель")
		}
		_, w, aerr := drv.importProfile(p.Slug, p.Text)
		if aerr != nil {
			return nil, aerr
		}
		if len(w) > 0 {
			warnings[p.Slug] = w
		}
	}
	if choice.PPPoE {
		if err := setPPPoESecret(sec.PPPoE.Username, sec.PPPoE.Password); err != nil {
			return nil, detailErr("пароль PPPoE не восстановлен — повторите", err.Error(), true)
		}
	}
	log.Printf("backup: из копии восстановлено профилей %d, PPPoE: %v", len(choice.Profiles), choice.PPPoE)
	return map[string]any{"restored": true, "warnings": warnings}, nil
}

var (
	peerUserRe   = regexp.MustCompile(`(?m)^user "([^"\n]*)"$`)
	secretLineRe = regexp.MustCompile(`^"([^"]*)"\s+\*\s+"([^"]*)"\s+\*\s*$`)
)

func readPPPoECredentials() (*pppoeCredentials, error) {
	peer, err := os.ReadFile(pppoePeerPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	secrets, err := os.ReadFile(pppoeChapSecret)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return pppoeCredentialsFrom(string(peer), string(secrets)), nil
}

func pppoeCredentialsFrom(peer, secrets string) *pppoeCredentials {
	m := peerUserRe.FindStringSubmatch(peer)
	if m == nil {
		return nil
	}
	for _, ln := range strings.Split(secrets, "\n") {
		if s := secretLineRe.FindStringSubmatch(strings.TrimSpace(ln)); s != nil && s[1] == m[1] {
			return &pppoeCredentials{Username: s[1], Password: s[2]}
		}
	}
	return nil
}
