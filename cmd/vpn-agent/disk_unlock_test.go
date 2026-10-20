package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/diskcrypt"
)

func TestParseAsk(t *testing.T) {
	r, err := parseAsk([]byte("[Ask]\nPID=42\nSocket=/run/systemd/ask-password/sck.1\nAcceptCached=1\nEcho=0\n" +
		"NotAfter=0\nMessage=Please enter passphrase for disk vpn-panel (system):\nIcon=drive-harddisk\n" +
		"Id=cryptsetup:/dev/disk/by-uuid/abc\n"))
	if err != nil {
		t.Fatal(err)
	}
	if r.pid != 42 || r.socket != "/run/systemd/ask-password/sck.1" || !r.isDisk() ||
		!strings.HasPrefix(r.message, "Please enter passphrase") || r.notAfter != 0 {
		t.Fatalf("разобрано не то: %+v", r)
	}
	if _, err := parseAsk([]byte("[Other]\nSocket=/x\n")); err == nil {
		t.Fatal("сокет вне раздела [Ask] не считается")
	}
	if r, _ := parseAsk([]byte("[Ask]\nSocket=/x\nId=other:thing\n")); r.isDisk() {
		t.Fatal("чужой запрос — не пароль диска")
	}
}

func TestAskAlive(t *testing.T) {
	me := askRequest{pid: os.Getpid()}
	if !me.alive(10) {
		t.Fatal("живой процесс без срока — в силе")
	}
	me.notAfter = 5
	if me.alive(10) {
		t.Fatal("срок вышел — не в силе")
	}
	if !me.deadline(10).IsZero() {
		t.Fatal("вышедший срок — без срока")
	}
	if (askRequest{pid: 1 << 30}).alive(0) {
		t.Fatal("мёртвый процесс — не в силе")
	}
	later := askRequest{notAfter: 1_000_000}
	if later.deadline(0).IsZero() {
		t.Fatal("срок впереди — есть")
	}
}

func TestAnswerPacket(t *testing.T) {
	if got := answerPacket([]byte("abc")); !bytes.Equal(got, []byte("+abc\x00")) {
		t.Fatalf("пакет %q", got)
	}
	if got := answerPacket(nil); !bytes.Equal(got, []byte("+\x00")) {
		t.Fatalf("пустой ответ %q", got)
	}
}

func TestAskAgentPending(t *testing.T) {
	dir := t.TempDir()
	write := func(name, id string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("[Ask]\nSocket=/x\nId="+id+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := &askAgent{dir: dir, done: map[string]bool{}, answered: map[string]bool{}}
	first := write("ask.aaa", "cryptsetup:/dev/x")
	write(".ask.bbb.tmp", "cryptsetup:/dev/x")
	write("other", "cryptsetup:/dev/x")
	reqs := a.pending()
	if len(reqs) != 1 || reqs[0].path != first {
		t.Fatalf("ждали один запрос ask.*, получили %+v", reqs)
	}
	a.done[first] = true
	if len(a.pending()) != 0 {
		t.Fatal("отвеченный запрос не предлагается снова")
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	a.pending()
	if a.done[first] {
		t.Fatal("запись об исчезнувшем файле убирается")
	}
}

func TestIsVirtualTerminal(t *testing.T) {
	for dev, want := range map[string]bool{"/dev/tty0": true, "/dev/tty1": true, "/dev/ttyS0": false,
		"/dev/ttyUSB0": false, "/dev/console": false, "/dev/hvc0": false} {
		if isVirtualTerminal(dev) != want {
			t.Errorf("%s: %v", dev, !want)
		}
	}
}

func TestStarLine(t *testing.T) {
	var out bytes.Buffer
	l := &starLine{w: &out, prefix: "> "}
	_, _ = l.Write([]byte("*"))
	_, _ = l.Write([]byte("*"))
	_, _ = l.Write([]byte("\b \b"))
	if l.n != 1 || !strings.HasSuffix(out.String(), "> *") {
		t.Fatalf("звёздочек %d, вывод %q", l.n, out.String())
	}
	out.Reset()
	l.setCaps(true)
	s := out.String()
	if !strings.Contains(s, diskcrypt.Text("vp:caps")) || !strings.HasSuffix(s, "D") {
		t.Fatalf("подсказка о Caps Lock и возврат курсора: %q", s)
	}
	_, _ = l.Write([]byte(strings.Repeat("\b \b", 1)))
	if l.n != 0 {
		t.Fatal("стирание всей строки")
	}
	out.Reset()
	l.setCaps(false)
	if strings.Contains(out.String(), diskcrypt.Text("vp:caps")) {
		t.Fatal("подсказка снята")
	}
}

func TestSplashSetting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "plymouthd.defaults")
	if err := os.WriteFile(p, []byte("[Daemon]\nShowDelay=0\nDeviceTimeout=8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d, ok := plymouthSetting(p, "DeviceTimeout"); !ok || d.Seconds() != 8 {
		t.Fatalf("срок %v %v", d, ok)
	}
	if _, ok := plymouthSetting(p, "Nothing"); ok {
		t.Fatal("нет ключа — нет срока")
	}
	if _, ok := plymouthSetting(filepath.Join(dir, "нет"), "DeviceTimeout"); ok {
		t.Fatal("нет файла — нет срока")
	}
}
