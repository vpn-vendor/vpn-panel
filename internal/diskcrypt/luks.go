package diskcrypt

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func ParseSlots(dump []byte) ([]int, error) {
	var meta struct {
		Keyslots map[string]json.RawMessage `json:"keyslots"`
	}
	if err := json.Unmarshal(dump, &meta); err != nil {
		return nil, err
	}
	out := make([]int, 0, len(meta.Keyslots))
	for k := range meta.Keyslots {
		n, err := strconv.Atoi(k)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	sort.Ints(out)
	return out, nil
}

var unlockedRe = regexp.MustCompile(`(?m)^Key slot (\d+) unlocked\.`)

func ParseUnlockedSlot(out string) int {
	m := unlockedRe.FindStringSubmatch(out)
	if m == nil {
		return -1
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		return -1
	}
	return n
}

func ParseStatusDevice(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && k == "device" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

type Header struct {
	Cipher   string
	KeyBits  int
	Slots    int
	Discards bool
}

type luksMeta struct {
	Keyslots map[string]struct {
		KeySize int `json:"key_size"`
		KDF     KDF `json:"kdf"`
	} `json:"keyslots"`
	Segments map[string]struct {
		Encryption string `json:"encryption"`
	} `json:"segments"`
	Config struct {
		Flags []string `json:"flags"`
	} `json:"config"`
}

func ParseHeader(dump []byte) (Header, error) {
	var m luksMeta
	if err := json.Unmarshal(dump, &m); err != nil {
		return Header{}, err
	}
	h := Header{Slots: len(m.Keyslots)}
	if seg, ok := m.Segments["0"]; ok {
		h.Cipher = seg.Encryption
	}
	for _, ks := range m.Keyslots {
		h.KeyBits = ks.KeySize * 8
		break
	}
	for _, f := range m.Config.Flags {
		if f == "allow-discards" {
			h.Discards = true
		}
	}
	return h, nil
}

type KDF struct {
	Type   string `json:"type"`
	Time   int    `json:"time"`
	Memory int    `json:"memory"`
	CPUs   int    `json:"cpus"`
}

func SlotKDF(dump []byte, slot int) (KDF, error) {
	var m luksMeta
	if err := json.Unmarshal(dump, &m); err != nil {
		return KDF{}, err
	}
	ks, ok := m.Keyslots[strconv.Itoa(slot)]
	if !ok {
		return KDF{}, errNoSlot
	}
	if ks.KDF.Type != "argon2id" || ks.KDF.Time < 1 || ks.KDF.Memory < 1 || ks.KDF.CPUs < 1 {
		return KDF{}, errNoSlot
	}
	return ks.KDF, nil
}

var errNoSlot = errors.New("у слота нет цены попытки argon2id")

func ParseCryptName(out string) string {
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == "crypt" {
			return f[0]
		}
	}
	return ""
}

func InitramfsLayout(keyboard string) string {
	for _, line := range strings.Split(keyboard, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && k == "XKBLAYOUT" {
			first, _, _ := strings.Cut(strings.Trim(v, `"' `), ",")
			return first
		}
	}
	return ""
}

func InitramfsHasKeymap(listing string) bool {
	for _, line := range strings.Split(listing, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		name := f[len(f)-1]
		if strings.HasSuffix(name, ".kmap") || strings.HasSuffix(name, ".kmap.gz") ||
			strings.Contains(name, "/keymaps/") || strings.HasSuffix(name, "cached_setup_keyboard.sh") {
			return true
		}
	}
	return false
}
