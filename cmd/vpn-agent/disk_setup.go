package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/devmode"
	"github.com/vpn-vendor/vpn-panel-core/internal/diskcrypt"
	"github.com/vpn-vendor/vpn-panel-core/internal/diskpass"
)

const (
	diskMapping        = "system"
	tempKeyPath        = "/etc/cryptsetup-keys.d/system.key"
	tempKeyConf        = "/etc/dracut.conf.d/90-vpn-panel-first-boot-key.conf"
	tempKeyInInitramfs = "etc/cryptsetup-keys.d/system.key"
	askID              = "vpn-panel-disk-setup"

	unlockIterMS = 5000

	cryptsetupNoKey = 2
)

func runDiskSetup() int {
	if devmode.Enabled {
		log.Print("disk-setup: в сборке разработчика не выполняется")
		return 1
	}
	human := newBootHuman()
	if restore, err := usKeymap(); err != nil {
		log.Printf("disk-setup: %v", err)
	} else {
		defer restore()
	}
	if err := diskSetup(human); err != nil {
		log.Printf("disk-setup: %v", err)
		_ = human.Tell(diskcrypt.MsgFailed)
		return 1
	}
	return 0
}

func diskSetup(human *bootHuman) error {
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	pol, err := diskpass.Builtin(host)
	if err != nil {
		return err
	}
	vol, err := openLuksVolume(diskMapping)
	if err != nil {
		return err
	}
	boot, err := newBootFiles()
	if err != nil {
		return err
	}
	return diskcrypt.Run(vol, boot, human, pol)
}

type luksVolume struct{ bin, dev string }

func openLuksVolume(name string) (*luksVolume, error) {
	bin, err := findBinary([]string{"/usr/sbin/cryptsetup", "/sbin/cryptsetup"})
	if err != nil {
		return nil, err
	}
	out, err := exec.Command(bin, "status", name).Output() //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("том %s не открыт: %w", name, err)
	}
	dev := diskcrypt.ParseStatusDevice(string(out))
	if dev == "" {
		return nil, fmt.Errorf("устройство тома %s не найдено", name)
	}
	return &luksVolume{bin: bin, dev: dev}, nil
}

func (v *luksVolume) run(secrets [][]byte, args ...string) (string, int, error) {
	cmd := exec.Command(v.bin, args...) //nolint:gosec
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	type channel struct {
		r, w   *os.File
		secret []byte
	}
	var chans []channel
	for _, s := range secrets {
		r, w, err := os.Pipe()
		if err != nil {
			return "", -1, err
		}
		cmd.ExtraFiles = append(cmd.ExtraFiles, r)
		chans = append(chans, channel{r: r, w: w, secret: s})
	}
	if err := cmd.Start(); err != nil {
		for _, c := range chans {
			_ = c.r.Close()
			_ = c.w.Close()
		}
		return "", -1, err
	}
	for _, c := range chans {
		_ = c.r.Close()

		_, werr := c.w.Write(c.secret)
		if cerr := c.w.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return "", -1, werr
		}
	}
	err := cmd.Wait()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		return out.String(), -1, err
	}
	return out.String(), code, nil
}

func fd(n int) string { return "/dev/fd/" + strconv.Itoa(n) }

func (v *luksVolume) Slots() ([]int, error) {
	out, code, err := v.run(nil, "luksDump", "--dump-json-metadata", v.dev)
	if err != nil || code != 0 {
		return nil, fmt.Errorf("слоты тома: код %d: %w", code, err)
	}
	return diskcrypt.ParseSlots([]byte(out))
}

func (v *luksVolume) SlotOpenedBy(key []byte) (int, error) {
	out, code, err := v.run([][]byte{key}, "open", "--test-passphrase", "-v", "--key-file", fd(3), v.dev)
	switch {
	case err != nil:
		return -1, err
	case code == cryptsetupNoKey:
		return -1, nil
	case code != 0:
		return -1, fmt.Errorf("проверка ключа: код %d", code)
	}
	return diskcrypt.ParseUnlockedSlot(out), nil
}

func (v *luksVolume) AddKey(existing, newKey []byte) error {
	_, code, err := v.run([][]byte{existing, newKey}, "luksAddKey", "--batch-mode",
		"--pbkdf", "argon2id", "--iter-time", strconv.Itoa(unlockIterMS),
		"--key-file", fd(3), v.dev, fd(4))
	return cryptErr("новый слот", code, err)
}

func (v *luksVolume) notLast() error {
	slots, err := v.Slots()
	if err != nil {
		return err
	}
	if len(slots) < 2 {
		return errors.New("отказ: это последний слот тома")
	}
	return nil
}

func (v *luksVolume) KillSlot(slot int, auth []byte) error {
	if err := v.notLast(); err != nil {
		return err
	}
	_, code, err := v.run([][]byte{auth}, "luksKillSlot", "--batch-mode", "--key-file", fd(3), v.dev, strconv.Itoa(slot))
	return cryptErr("уничтожение слота", code, err)
}

func (v *luksVolume) RemoveKey(key []byte) error {
	if err := v.notLast(); err != nil {
		return err
	}
	_, code, err := v.run([][]byte{key}, "luksRemoveKey", "--batch-mode", "--key-file", fd(3), v.dev)
	return cryptErr("уничтожение слота ключа", code, err)
}

func cryptErr(what string, code int, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if code != 0 {
		return fmt.Errorf("%s: код cryptsetup %d", what, code)
	}
	return nil
}

type bootFiles struct{ updateInitramfs, lsinitrd string }

func newBootFiles() (*bootFiles, error) {
	upd, err := findBinary([]string{"/usr/sbin/update-initramfs", "/sbin/update-initramfs"})
	if err != nil {
		return nil, err
	}
	ls, err := findBinary([]string{"/usr/bin/lsinitrd", "/bin/lsinitrd"})
	if err != nil {
		return nil, err
	}
	return &bootFiles{updateInitramfs: upd, lsinitrd: ls}, nil
}

func (b *bootFiles) KeyFile() ([]byte, bool, error) {
	key, err := os.ReadFile(tempKeyPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	return key, err == nil, err
}

func (b *bootFiles) RemoveKeyFile() error { return durable.Remove(tempKeyPath) }

func (b *bootFiles) RemoveKeyConf() error { return durable.Remove(tempKeyConf) }

func (b *bootFiles) RebuildInitramfs() error {
	out, err := exec.Command(b.updateInitramfs, "-u", "-k", "all").CombinedOutput() //nolint:gosec
	if err != nil {
		return fmt.Errorf("%w: %s", err, lastLine(out))
	}
	return nil
}

func (b *bootFiles) InitramfsKey() (diskcrypt.Presence, error) {
	images, err := filepath.Glob("/boot/initrd.img-*")
	if err != nil {
		return 0, err
	}
	total, with := 0, 0
	for _, img := range images {
		if fi, err := os.Lstat(img); err != nil || !fi.Mode().IsRegular() {
			continue
		}
		total++
		out, err := exec.Command(b.lsinitrd, img).Output() //nolint:gosec
		if err != nil {
			return 0, fmt.Errorf("состав %s: %w", img, err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasSuffix(strings.TrimSpace(line), tempKeyInInitramfs) {
				with++
				break
			}
		}
	}
	switch {
	case total == 0:
		return 0, errors.New("в /boot нет initramfs")
	case with == 0:
		return diskcrypt.KeyNowhere, nil
	case with == total:
		return diskcrypt.KeyEverywhere, nil
	}
	return diskcrypt.KeySome, nil
}

func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return lines[len(lines)-1]
}

type bootHuman struct {
	ask, plymouth string
	graphic       bool

	timeout int
}

func newBootHuman() *bootHuman {
	h := &bootHuman{}
	h.ask, _ = findBinary([]string{"/usr/bin/systemd-ask-password", "/bin/systemd-ask-password"})
	h.plymouth, _ = findBinary([]string{"/usr/bin/plymouth", "/bin/plymouth"})
	h.graphic = h.plymouth != "" && exec.Command(h.plymouth, "--ping").Run() == nil //nolint:gosec
	return h
}

func (h *bootHuman) text(code string) string {
	if h.graphic {
		return code
	}
	return diskcrypt.Text(code)
}

func (h *bootHuman) Ask(p diskcrypt.Prompt) ([]byte, error) {
	if h.ask == "" {
		return nil, errors.New("нет systemd-ask-password")
	}

	out, err := exec.Command(h.ask, "--timeout="+strconv.Itoa(h.timeout), "--id="+askID, h.text(string(p))).Output() //nolint:gosec
	if err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out, []byte("\n")), nil
}

func (h *bootHuman) Tell(m diskcrypt.Message) error {
	if h.graphic {
		return exec.Command(h.plymouth, "display-message", "--text="+string(m)).Run() //nolint:gosec
	}
	console, err := os.OpenFile("/dev/console", os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintf(console, "\n%s\n", h.text(string(m)))
	if cerr := console.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

func usKeymap() (restore func(), err error) {
	loadkeys, err := findBinary([]string{"/usr/bin/loadkeys", "/bin/loadkeys"})
	if err != nil {
		return func() {}, err
	}

	if out, err := exec.Command(loadkeys, "-C", "/dev/tty1", "-q", "us").CombinedOutput(); err != nil { //nolint:gosec
		return func() {}, fmt.Errorf("английская раскладка не включена: %v: %s", err, lastLine(out))
	}
	return func() {
		setupcon, err := findBinary([]string{"/usr/bin/setupcon", "/bin/setupcon"})
		if err != nil {
			return
		}
		if out, err := exec.Command(setupcon, "--force", "--keyboard-only").CombinedOutput(); err != nil { //nolint:gosec
			log.Printf("раскладка системы не возвращена: %v: %s", err, lastLine(out))
		}
	}, nil
}
