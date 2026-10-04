package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/devmode"
	"github.com/vpn-vendor/vpn-panel-core/internal/diskcrypt"
	"github.com/vpn-vendor/vpn-panel-core/internal/diskpass"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
)

const (
	diskChangeRequest = "/etc/vpn-panel/disk-change.request"
	diskChangeLast    = "/etc/vpn-panel/disk-change.last"

	changeTries = 3

	changeAnswerSeconds = 300

	codeDiskParams  = 2001
	codeDiskState   = 2002
	codeDiskWrite   = 2003
	codeDiskTooMany = 2004
)

type diskApplier struct {
	mu sync.Mutex

	keymapMu    sync.Mutex
	keymapStamp time.Time
	keymap      string

	toggles *ratelimit.Limiter
}

func newDiskApplier() *diskApplier {
	return &diskApplier{toggles: ratelimit.New(6, 1, time.Minute)}
}

func rootCrypt() (string, error) {
	findmnt, err := findBinary([]string{"/usr/bin/findmnt", "/bin/findmnt"})
	if err != nil {
		return "", err
	}
	lsblk, err := findBinary([]string{"/usr/bin/lsblk", "/bin/lsblk"})
	if err != nil {
		return "", err
	}
	src, err := exec.Command(findmnt, "-no", "SOURCE", "/").Output() //nolint:gosec
	if err != nil {
		return "", err
	}
	dev := strings.TrimSpace(string(src))
	if !strings.HasPrefix(dev, "/dev/") {
		return "", nil
	}
	out, err := exec.Command(lsblk, "-rno", "NAME,TYPE", "-s", dev).Output() //nolint:gosec
	if err != nil {
		return "", err
	}
	return diskcrypt.ParseCryptName(string(out)), nil
}

func (d *diskApplier) diskStatus(json.RawMessage) (any, *agentrpc.ErrorObject) {
	st := diskcrypt.Status{
		AESNI:            cpuHasAES(),
		FirstBootPending: fileExists(tempKeyPath),
		ChangeRequested:  fileExists(diskChangeRequest),
	}
	st.LastChange, st.LastChangeAt = lastChange()
	st.UnlockKeymap = d.unlockKeymap()
	name, err := rootCrypt()
	if err != nil || name == "" {
		return st, nil
	}
	vol, err := openLuksVolume(name)
	if err != nil {
		return st, nil
	}
	out, code, err := vol.run(nil, "luksDump", "--dump-json-metadata", vol.dev)
	if err != nil || code != 0 {
		return st, nil
	}
	h, err := diskcrypt.ParseHeader([]byte(out))
	if err != nil {
		return st, nil
	}
	st.Encrypted = true
	st.Cipher, st.KeyBits, st.Slots, st.Discards = h.Cipher, h.KeyBits, h.Slots, h.Discards
	return st, nil
}

func (d *diskApplier) unlockKeymap() string {
	rel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	ver := strings.TrimSpace(string(rel))

	if ver == "" || strings.Trim(ver, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-+_") != "" {
		return ""
	}
	img := "/boot/initrd.img-" + ver
	fi, err := os.Stat(img) //nolint:gosec
	if err != nil {
		return ""
	}
	d.keymapMu.Lock()
	defer d.keymapMu.Unlock()
	if fi.ModTime().Equal(d.keymapStamp) && d.keymap != "" {
		return d.keymap
	}
	lsinitrd, err := findBinary([]string{"/usr/bin/lsinitrd", "/bin/lsinitrd"})
	if err != nil {
		return ""
	}
	out, err := exec.Command(lsinitrd, img).Output() //nolint:gosec
	if err != nil {
		return ""
	}

	kb, err := exec.Command(lsinitrd, "-f", "etc/default/keyboard", img).Output() //nolint:gosec
	if err != nil {
		return ""
	}
	d.keymap = "us"

	if l := diskcrypt.InitramfsLayout(string(kb)); diskcrypt.InitramfsHasKeymap(string(out)) || (l != "" && l != "us") {
		d.keymap = "system"
	}
	d.keymapStamp = fi.ModTime()
	return d.keymap
}

type diskChangeParams struct {
	Requested *bool `json:"requested"`
}

func (d *diskApplier) diskChangeRequest(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p diskChangeParams
	if err := json.Unmarshal(raw, &p); err != nil || p.Requested == nil {
		return nil, &agentrpc.ErrorObject{Code: codeDiskParams, Message: "запрос составлен неверно"}
	}
	if !d.toggles.Allow("disk") {
		return nil, agentrpc.Busy(codeDiskTooMany, "Слишком частые переключения. Подождите минуту.", d.toggles.RetryIn("disk"))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !*p.Requested {
		if err := durable.Remove(diskChangeRequest); err != nil {
			return nil, &agentrpc.ErrorObject{Code: codeDiskWrite, Message: "Не удалось отменить смену пароля."}
		}
		return d.diskStatus(nil)
	}
	st, _ := d.diskStatus(nil)
	if s := st.(diskcrypt.Status); !s.Encrypted || s.FirstBootPending {
		return nil, &agentrpc.ErrorObject{Code: codeDiskState,
			Message: "Сменить пароль можно только на зашифрованном диске, после того как пароль задан при первом включении."}
	}

	if err := durable.Write(diskChangeRequest, nil, 0o600); err != nil {
		return nil, &agentrpc.ErrorObject{Code: codeDiskWrite, Message: "Не удалось запомнить запрос смены пароля."}
	}
	return d.diskStatus(nil)
}

func lastChange() (outcome, at string) {
	data, err := os.ReadFile(diskChangeLast)
	if err != nil {
		return "", ""
	}
	outcome, at, _ = strings.Cut(strings.TrimSpace(string(data)), " ")
	return outcome, at
}

func writeLastChange(outcome string) {
	line := outcome + " " + time.Now().UTC().Format(time.RFC3339) + "\n"
	if err := durable.Write(diskChangeLast, []byte(line), 0o600); err != nil {
		log.Printf("disk-change: итог не записан: %v", err)
	}
}

func runDiskChange() int {
	if devmode.Enabled {
		log.Print("disk-change: в сборке разработчика не выполняется")
		return 1
	}
	human, closeConsole, err := newConsoleHuman(changeAnswerSeconds * time.Second)
	if err != nil {

		log.Printf("disk-change: консоль: %v", err)
		writeLastChange("failed")
		return 1
	}
	defer closeConsole()
	restore, err := usKeymap()
	if err != nil {

		log.Printf("disk-change: %v", err)
		_ = human.Tell(diskcrypt.MsgKept)
		writeLastChange("failed")
		_ = durable.Remove(diskChangeRequest)
		return 1
	}
	defer restore()
	outcome, err := diskChange(human)
	if err != nil {
		log.Printf("disk-change: %v", err)
		_ = human.Tell(diskcrypt.MsgChangeFailed)
		writeLastChange("failed")
		return 1
	}
	names := map[diskcrypt.Outcome]string{diskcrypt.Changed: "changed", diskcrypt.Skipped: "skipped", diskcrypt.GaveUp: "gave_up"}
	log.Printf("disk-change: %s", names[outcome])
	writeLastChange(names[outcome])
	if err := durable.Remove(diskChangeRequest); err != nil {
		log.Printf("disk-change: отметка не снята: %v", err)
	}
	return 0
}

func diskChange(human diskcrypt.Human) (diskcrypt.Outcome, error) {
	host, err := os.Hostname()
	if err != nil {
		return diskcrypt.Skipped, err
	}
	pol, err := diskpass.Builtin(host)
	if err != nil {
		return diskcrypt.Skipped, err
	}
	name, err := rootCrypt()
	if err != nil {
		return diskcrypt.Skipped, err
	}
	if name == "" {
		return diskcrypt.Skipped, errors.New("корень не зашифрован")
	}
	vol, err := openLuksVolume(name)
	if err != nil {
		return diskcrypt.Skipped, err
	}
	return diskcrypt.Change(vol, human, pol, changeTries)
}

func (v *luksVolume) AddKeyLike(existing, newKey []byte, like int) error {
	args := []string{"luksAddKey", "--batch-mode", "--pbkdf", "argon2id"}
	out, code, err := v.run(nil, "luksDump", "--dump-json-metadata", v.dev)
	if err != nil || code != 0 {
		return cryptErr("заголовок тома", code, err)
	}
	if k, kerr := diskcrypt.SlotKDF([]byte(out), like); kerr == nil {
		args = append(args, "--pbkdf-force-iterations", strconv.Itoa(k.Time),
			"--pbkdf-memory", strconv.Itoa(k.Memory), "--pbkdf-parallel", strconv.Itoa(k.CPUs))
	} else {
		args = append(args, "--iter-time", strconv.Itoa(unlockIterMS))
	}
	args = append(args, "--key-file", fd(3), v.dev, fd(4))
	_, code, err = v.run([][]byte{existing, newKey}, args...)
	return cryptErr(fmt.Sprintf("новый слот по образцу слота %d", like), code, err)
}
