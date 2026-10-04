package diskcrypt

import (
	"errors"
	"fmt"

	"github.com/vpn-vendor/vpn-panel-core/internal/diskpass"
)

type Volume interface {
	Slots() ([]int, error)

	SlotOpenedBy(key []byte) (int, error)

	AddKey(existing, newKey []byte) error

	KillSlot(slot int, auth []byte) error

	RemoveKey(key []byte) error
}

type Boot interface {
	KeyFile() (key []byte, ok bool, err error)
	RemoveKeyFile() error

	RemoveKeyConf() error
	RebuildInitramfs() error

	InitramfsKey() (Presence, error)
}

type Presence int

const (
	KeyNowhere Presence = iota

	KeySome
	KeyEverywhere
)

type Prompt string

type Message string

const (
	PromptNew    Prompt  = "vp:new"
	PromptRepeat Prompt  = "vp:repeat"
	MsgIntro     Message = "vp:intro"
	MsgMismatch  Message = "vp:mismatch"
	MsgDone      Message = "vp:done"

	MsgFailed Message = "vp:failed"
)

func ReasonMessage(r diskpass.Reason) Message { return Message("vp:" + string(r)) }

type Human interface {
	Ask(p Prompt) ([]byte, error)
	Tell(m Message) error
}

type Step int

const (
	StepNone Step = iota

	StepCleanup

	StepFinish

	StepFull
)

type Facts struct {
	KeyFile    bool
	TempSlot   int
	OtherSlots []int
	Initramfs  Presence
}

func Decide(f Facts) Step {
	switch {
	case !f.KeyFile:
		return StepNone
	case f.TempSlot < 0:
		return StepCleanup
	case f.Initramfs != KeyEverywhere && len(f.OtherSlots) > 0:
		return StepFinish
	default:
		return StepFull
	}
}

var ErrState = errors.New("состояние тома не распознано")

func Run(v Volume, b Boot, h Human, pol *diskpass.Policy) error {
	f, key, err := facts(v, b)
	if err != nil {
		return err
	}
	switch Decide(f) {
	case StepNone:
		return nil
	case StepCleanup:
		return cleanup(b, f.Initramfs != KeyNowhere)
	case StepFinish:
		if err := v.RemoveKey(key); err != nil {
			return fmt.Errorf("уничтожение временного слота: %w", err)
		}
		return cleanup(b, f.Initramfs != KeyNowhere)
	}

	for _, s := range f.OtherSlots {
		if err := v.KillSlot(s, key); err != nil {
			return fmt.Errorf("слот прерванной попытки: %w", err)
		}
	}
	if err := h.Tell(MsgIntro); err != nil {
		return err
	}
	pw, err := askNew(h, pol)
	if err != nil {
		return err
	}
	defer wipe(pw)
	if err := v.AddKey(key, pw); err != nil {
		return fmt.Errorf("новый слот: %w", err)
	}
	slot, err := v.SlotOpenedBy(pw)
	if err != nil {
		return err
	}
	if slot < 0 || slot == f.TempSlot {
		return fmt.Errorf("новый пароль не открывает том: %w", ErrState)
	}
	if err := b.RemoveKeyConf(); err != nil {
		return err
	}
	if err := b.RebuildInitramfs(); err != nil {
		return fmt.Errorf("пересборка initramfs: %w", err)
	}
	if p, err := b.InitramfsKey(); err != nil || p != KeyNowhere {
		return fmt.Errorf("временный ключ остался в initramfs: %w", errors.Join(err, ErrState))
	}
	if err := v.RemoveKey(key); err != nil {
		return fmt.Errorf("уничтожение временного слота: %w", err)
	}
	if err := b.RemoveKeyFile(); err != nil {
		return err
	}
	return h.Tell(MsgDone)
}

func facts(v Volume, b Boot) (Facts, []byte, error) {
	key, ok, err := b.KeyFile()
	if err != nil || !ok {
		return Facts{KeyFile: false, TempSlot: -1}, nil, err
	}
	f := Facts{KeyFile: true}
	if f.TempSlot, err = v.SlotOpenedBy(key); err != nil {
		return f, nil, err
	}
	slots, err := v.Slots()
	if err != nil {
		return f, nil, err
	}
	for _, s := range slots {
		if s != f.TempSlot {
			f.OtherSlots = append(f.OtherSlots, s)
		}
	}
	if f.Initramfs, err = b.InitramfsKey(); err != nil {
		return f, nil, err
	}
	return f, key, nil
}

func cleanup(b Boot, rebuild bool) error {
	if err := b.RemoveKeyConf(); err != nil {
		return err
	}
	if rebuild {
		if err := b.RebuildInitramfs(); err != nil {
			return fmt.Errorf("пересборка initramfs: %w", err)
		}
	}
	return b.RemoveKeyFile()
}

func askNew(h Human, pol *diskpass.Policy) ([]byte, error) {
	for {
		pw, err := h.Ask(PromptNew)
		if err != nil {
			return nil, err
		}
		if r := pol.Check(string(pw)); r != diskpass.OK {
			wipe(pw)
			if err := h.Tell(ReasonMessage(r)); err != nil {
				return nil, err
			}
			continue
		}
		again, err := h.Ask(PromptRepeat)
		if err != nil {
			wipe(pw)
			return nil, err
		}
		same := string(again) == string(pw)
		wipe(again)
		if same {
			return pw, nil
		}
		wipe(pw)
		if err := h.Tell(MsgMismatch); err != nil {
			return nil, err
		}
	}
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
