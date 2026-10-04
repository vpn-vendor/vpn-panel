package diskcrypt

import (
	"fmt"

	"github.com/vpn-vendor/vpn-panel-core/internal/diskpass"
)

const (
	PromptCurrent   Prompt  = "vp:current"
	MsgChangeIntro  Message = "vp:change-intro"
	MsgCurrentWrong Message = "vp:current-wrong"
	MsgSame         Message = "vp:same"
	MsgChanged      Message = "vp:changed"
	MsgKept         Message = "vp:kept"

	MsgChangeFailed Message = "vp:change-failed"
)

type Outcome int

const (
	Skipped Outcome = iota

	GaveUp
	Changed
)

type Rekeyer interface {
	Volume

	AddKeyLike(existing, newKey []byte, like int) error
}

func Change(v Rekeyer, h Human, pol *diskpass.Policy, tries int) (Outcome, error) {
	if err := h.Tell(MsgChangeIntro); err != nil {
		return Skipped, err
	}
	cur, slot, out, err := askCurrent(v, h, tries)
	if err != nil || slot < 0 {
		return out, err
	}
	defer wipe(cur)
	var pw []byte
	for {
		p, err := askNew(h, pol)
		if err != nil {
			return Skipped, err
		}
		if string(p) != string(cur) {
			pw = p
			break
		}
		wipe(p)
		if err := h.Tell(MsgSame); err != nil {
			return Skipped, err
		}
	}
	defer wipe(pw)
	if err := v.AddKeyLike(cur, pw, slot); err != nil {
		return Skipped, fmt.Errorf("новый слот: %w", err)
	}
	ns, err := v.SlotOpenedBy(pw)
	if err != nil {
		return Skipped, err
	}
	if ns < 0 || ns == slot {
		return Skipped, fmt.Errorf("новый пароль не открывает том: %w", ErrState)
	}

	slots, err := v.Slots()
	if err != nil {
		return Skipped, err
	}
	for _, s := range slots {
		if s == ns {
			continue
		}
		if err := v.KillSlot(s, pw); err != nil {
			return Skipped, fmt.Errorf("прежний слот: %w", err)
		}
	}
	return Changed, h.Tell(MsgChanged)
}

func askCurrent(v Volume, h Human, tries int) (cur []byte, slot int, out Outcome, err error) {
	for i := 0; i < tries; i++ {
		pw, err := h.Ask(PromptCurrent)
		if err != nil {
			return nil, -1, Skipped, err
		}
		if len(pw) == 0 {
			return nil, -1, Skipped, h.Tell(MsgKept)
		}
		s, err := v.SlotOpenedBy(pw)
		if err != nil {
			wipe(pw)
			return nil, -1, Skipped, err
		}
		if s >= 0 {
			return pw, s, Skipped, nil
		}
		wipe(pw)
		if err := h.Tell(MsgCurrentWrong); err != nil {
			return nil, -1, Skipped, err
		}
	}
	return nil, -1, GaveUp, h.Tell(MsgKept)
}
