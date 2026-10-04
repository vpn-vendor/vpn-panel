package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupcode"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

const (
	copyPassword = "Kolokol-Sirena-Tuman-47" //nolint:gosec
	wgPrivate    = "6HrAtQNTBhaOAxo2rEyOEqYnLXQ5U8DdAxIQyfaFvV4="
	pppoePass    = "provider-pass-9931"
)

type restored struct {
	sec    backupSecrets
	choice restoreChoice
}

func testBackup(t *testing.T) (*backupApplier, *[]restored) {
	t.Helper()
	var got []restored
	b := &backupApplier{
		codes:   backupcode.New(),
		limiter: ratelimit.New(100, 1, time.Minute),
		collect: func() (backupSecrets, error) {
			return backupSecrets{
				Version:  secretsVersion,
				Profiles: []secretProfile{{Protocol: "wireguard", Slug: "office", Text: "[Interface]\nPrivateKey = " + wgPrivate + "\n"}},
				PPPoE:    &pppoeCredentials{Username: "client-42", Password: pppoePass},
			}, nil
		},
		restore: func(s backupSecrets, c restoreChoice) (map[string]any, *agentrpc.ErrorObject) {
			got = append(got, restored{s, c})
			return map[string]any{"restored": true}, nil
		},
	}
	return b, &got
}

func copyDocument(t *testing.T, kind backupfile.Kind) json.RawMessage {
	t.Helper()
	raw, err := backupfile.Marshal(&backupfile.Document{
		Format: backupfile.FormatName, FormatVersion: backupfile.FormatVersion, Kind: kind,
		PanelVersion: "0.3.0", CreatedAt: time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC),
		Sections: map[string]backupfile.Section{"qos": {Version: 1, Data: json.RawMessage(`{"down_kbit":1000}`)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func call(t *testing.T, h agentrpc.Handler, params any) (map[string]json.RawMessage, *agentrpc.ErrorObject) {
	t.Helper()
	raw, _ := json.Marshal(params)
	res, aerr := h(raw)
	if aerr != nil {
		return nil, aerr
	}
	out, _ := json.Marshal(res)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	return m, nil
}

func issue(t *testing.T, b *backupApplier) string {
	t.Helper()
	m, aerr := call(t, b.backupCode, map[string]any{})
	if aerr != nil {
		t.Fatal(aerr)
	}
	var code string
	_ = json.Unmarshal(m["code"], &code)
	return code
}

func exportCopy(t *testing.T, b *backupApplier, code string) string {
	t.Helper()
	m, aerr := call(t, b.backupExport, map[string]any{"code": code, "password": copyPassword, "document": copyDocument(t, backupfile.KindCopy)})
	if aerr != nil {
		t.Fatalf("выгрузка: %+v", aerr)
	}
	var file string
	_ = json.Unmarshal(m["file"], &file)
	return file
}

func TestExportOpenKeepsSecretsInAgent(t *testing.T) {
	b, got := testBackup(t)
	file := exportCopy(t, b, issue(t, b))
	for _, secret := range []string{wgPrivate, pppoePass} {
		if strings.Contains(file, secret) {
			t.Fatal("секрет виден в файле копии")
		}
	}
	m, aerr := call(t, b.backupOpen, map[string]any{"password": copyPassword, "file": file})
	if aerr != nil {
		t.Fatalf("открытие: %+v", aerr)
	}
	all, _ := json.Marshal(m)
	for _, secret := range []string{wgPrivate, pppoePass} {
		if strings.Contains(string(all), secret) {
			t.Fatalf("секрет ушёл панели при открытии копии: %s", all)
		}
	}
	if !strings.Contains(string(m["secrets"]), `"office"`) || !strings.Contains(string(m["secrets"]), `"pppoe":true`) {
		t.Fatalf("перечень секретов: %s", m["secrets"])
	}
	if !strings.Contains(string(m["document"]), `"down_kbit":1000`) {
		t.Fatalf("документ не вернулся: %s", m["document"])
	}

	if _, aerr := call(t, b.backupApplySecrets, map[string]any{"password": copyPassword, "file": file,
		"restore": map[string]any{"profiles": []map[string]string{{"protocol": "wireguard", "slug": "office"}}, "pppoe": true}}); aerr != nil {
		t.Fatal(aerr)
	}
	if len(*got) != 1 || len((*got)[0].sec.Profiles) != 1 || (*got)[0].sec.Profiles[0].Text == "" || (*got)[0].sec.PPPoE.Password != pppoePass ||
		len((*got)[0].choice.Profiles) != 1 || !(*got)[0].choice.PPPoE {
		t.Fatalf("восстановлено не то: %+v", *got)
	}
	if _, aerr := call(t, b.backupApplySecrets, map[string]any{"password": copyPassword, "file": file,
		"restore": map[string]any{"profiles": []map[string]string{{"protocol": "openvpn", "slug": "vpn2"}}}}); aerr == nil || aerr.Code != codeBackupApply {
		t.Fatalf("профиль, которого нет в копии: %+v", aerr)
	}
}

func TestExportNeedsCode(t *testing.T) {
	b, _ := testBackup(t)
	doc := copyDocument(t, backupfile.KindCopy)
	if _, aerr := call(t, b.backupExport, map[string]any{"code": "2222-2222", "password": copyPassword, "document": doc}); aerr == nil || aerr.Code != codeBackupNoCode {
		t.Fatalf("выгрузка без выданного кода: %+v", aerr)
	}
	code := issue(t, b)
	if _, aerr := call(t, b.backupExport, map[string]any{"code": code, "password": "12345", "document": doc}); aerr == nil || aerr.Code != codeBackupWeak {
		t.Fatalf("слабый пароль: %+v", aerr)
	}
	if _, aerr := call(t, b.backupExport, map[string]any{"code": code, "password": copyPassword, "document": copyDocument(t, backupfile.KindTemplate)}); aerr == nil || aerr.Code != codeBackupFile {
		t.Fatalf("шаблон вместо копии: %+v", aerr)
	}
	if _, aerr := call(t, b.backupExport, map[string]any{"code": "2222-2222", "password": copyPassword, "document": doc}); aerr == nil || aerr.Code != codeBackupWrongCode {
		t.Fatalf("чужой код: %+v", aerr)
	}
	exportCopy(t, b, code)
	if _, aerr := call(t, b.backupExport, map[string]any{"code": code, "password": copyPassword, "document": doc}); aerr == nil || aerr.Code != codeBackupNoCode {
		t.Fatalf("код сработал второй раз: %+v", aerr)
	}
}

func TestOpenRefusesWrongPasswordAndTamper(t *testing.T) {
	b, _ := testBackup(t)
	file := exportCopy(t, b, issue(t, b))
	other := "Drugoj-Parol-Kopii-12" //nolint:gosec
	if _, aerr := call(t, b.backupOpen, map[string]any{"password": other, "file": file}); aerr == nil || aerr.Code != codeBackupPassword {
		t.Fatalf("чужой пароль: %+v", aerr)
	}
	bad := []byte(file)
	bad[len(bad)/2] ^= 0x01
	if _, aerr := call(t, b.backupOpen, map[string]any{"password": copyPassword, "file": string(bad)}); aerr == nil {
		t.Fatal("изменённый файл открылся")
	}
	if _, aerr := call(t, b.backupOpen, map[string]any{"password": copyPassword, "file": "не base64 !"}); aerr == nil || aerr.Code != codeBackupFile {
		t.Fatalf("мусор вместо файла: %+v", aerr)
	}
}

func TestBackupRateLimited(t *testing.T) {
	b, _ := testBackup(t)
	b.limiter = ratelimit.New(2, 1, time.Hour)
	for i := 0; i < 2; i++ {
		_, _ = call(t, b.backupOpen, map[string]any{"password": copyPassword, "file": ""})
	}
	if _, aerr := call(t, b.backupOpen, map[string]any{"password": copyPassword, "file": ""}); aerr == nil || aerr.Code != codeBackupTooMany {
		t.Fatalf("перебор пароля не ограничен: %+v", aerr)
	}
}

func TestBackupSuccessNotCounted(t *testing.T) {
	b, _ := testBackup(t)
	file := exportCopy(t, b, issue(t, b))
	b.limiter = ratelimit.New(2, 1, time.Hour)
	for i := 0; i < 10; i++ {
		if _, aerr := call(t, b.backupOpen, map[string]any{"password": copyPassword, "file": file}); aerr != nil {
			t.Fatalf("удачное открытие %d упёрлось в предел: %+v", i, aerr)
		}
	}
}

func TestParseSecretsStrict(t *testing.T) {
	for name, c := range map[string]struct {
		raw  string
		want error
	}{
		"новее агента":     {`{"version":3}`, backupfile.ErrNewer},
		"без версии":       {`{"wireguard":{}}`, backupfile.ErrMalformed},
		"лишнее поле":      {`{"version":1,"shell":"x"}`, backupfile.ErrMalformed},
		"имя с путём":      {`{"version":1,"wireguard":{"../etc":"x"}}`, backupfile.ErrMalformed},
		"кавычка в пароле": {`{"version":1,"pppoe":{"username":"u","password":"a\"b"}}`, backupfile.ErrMalformed},
		"логин с пробелом": {`{"version":1,"pppoe":{"username":"u u","password":"ab"}}`, backupfile.ErrMalformed},
	} {
		if _, err := parseSecrets(json.RawMessage(c.raw)); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, ждали %v", name, err, c.want)
		}
	}
	if _, err := parseSecrets(json.RawMessage(`{"version":1,"wireguard":{"office":"x"},"pppoe":{"username":"u","password":"p w"}}`)); err != nil {
		t.Fatalf("контроль: годная секретная часть отвергнута: %v", err)
	}
}

func TestPPPoECredentialsRoundTrip(t *testing.T) {
	peer := pppoePeerContent("ens3", "client-42")
	secrets := "\"other\" * \"x\" *\n" + "\"client-42\" * \"" + "p@ss word" + "\" *\n"
	c := pppoeCredentialsFrom(peer, secrets)
	if c == nil || c.Username != "client-42" || c.Password != "p@ss word" {
		t.Fatalf("прочитано: %+v", c)
	}
	if pppoeCredentialsFrom(peer, "\"other\" * \"x\" *\n") != nil {
		t.Fatal("чужая строка принята за нашу")
	}
	if pppoeCredentialsFrom("noauth\n", secrets) != nil {
		t.Fatal("без логина в peer-файле найден пароль")
	}
}

func TestSecretsV1ReadAsV2(t *testing.T) {
	s, err := parseSecrets(json.RawMessage(`{"version":1,"wireguard":{"b":"wb","a":"wa"},"openvpn":{"c":"oc"},"pppoe":{"username":"u","password":"p"}}`))
	if err != nil {
		t.Fatal(err)
	}
	want := []secretProfile{{"openvpn", "c", "oc"}, {"wireguard", "a", "wa"}, {"wireguard", "b", "wb"}}
	if s.Version != secretsVersion || len(s.Profiles) != 3 || s.PPPoE == nil {
		t.Fatalf("перевод: %+v", s)
	}
	for i, p := range want {
		if s.Profiles[i] != p {
			t.Fatalf("профиль %d: %+v, ждали %+v", i, s.Profiles[i], p)
		}
	}
	for name, raw := range map[string]string{
		"повтор слага":    `{"version":2,"profiles":[{"protocol":"wireguard","slug":"a","text":"x"},{"protocol":"openvpn","slug":"a","text":"y"}]}`,
		"незнакомое поле": `{"version":2,"profiles":[],"extra":1}`,
		"без протокола":   `{"version":2,"profiles":[{"protocol":"","slug":"a","text":"x"}]}`,
	} {
		if _, err := parseSecrets(json.RawMessage(raw)); err != backupfile.ErrMalformed {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := parseSecrets(json.RawMessage(`{"version":3}`)); err != backupfile.ErrNewer {
		t.Fatalf("версия новее агента: %v", err)
	}
}

func TestCollectPPPoEOnlyInUse(t *testing.T) {
	inUse, read := pppoeInUse, readPPPoE
	t.Cleanup(func() { pppoeInUse, readPPPoE = inUse, read })
	readPPPoE = func() (*pppoeCredentials, error) {
		return &pppoeCredentials{Username: "client-42", Password: pppoePass}, nil
	}
	v := &vpnApplier{}
	pppoeInUse = func() bool { return false }
	if sec, err := v.collectSecrets(); err != nil || sec.PPPoE != nil {
		t.Fatalf("спящий PPPoE попал в копию: %+v %v", sec.PPPoE, err)
	}
	pppoeInUse = func() bool { return true }
	if sec, err := v.collectSecrets(); err != nil || sec.PPPoE == nil || sec.PPPoE.Password != pppoePass {
		t.Fatalf("действующий PPPoE не попал в копию: %+v %v", sec.PPPoE, err)
	}
}
