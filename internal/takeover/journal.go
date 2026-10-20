package takeover

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

func Digest(items []Item) string {
	type canon struct {
		ID     string `json:"id"`
		Kind   string `json:"kind"`
		Locked bool   `json:"locked"`
		Order  int    `json:"order"`
		Step1  []Op   `json:"step1"`
		Step3  []Op   `json:"step3"`
	}
	cs := make([]canon, 0, len(items))
	for _, it := range items {
		cs = append(cs, canon{it.ID, it.Kind, it.Locked, it.Order, it.Step1, it.Step3})
	}
	slices.SortFunc(cs, func(a, b canon) int { return strings.Compare(a.ID, b.ID) })
	data, _ := json.Marshal(cs)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

const opHashLen = 12

func OpKey(itemID string, i int, op Op) string {
	data, _ := json.Marshal(op)
	sum := sha256.Sum256(data)
	return itemID + "#" + strconv.Itoa(i) + "." + string(op.Kind) + "." + hex.EncodeToString(sum[:])[:opHashLen]
}

type Stage string

const (
	StageWindow    Stage = "window"
	StageFinishing Stage = "finishing"
	StageDone      Stage = "done"
	StagePartial   Stage = "partial"
)

const JournalSchema = 2

type Aside struct {
	Path  string `json:"path"`
	Saved string `json:"saved"`
	Mode  uint32 `json:"mode"`
	UID   int    `json:"uid"`
	GID   int    `json:"gid"`
}

type Mark struct {
	Key  string `json:"key"`
	Boot string `json:"boot"`
}

type Journal struct {
	Schema int `json:"schema"`

	Plan    Plan   `json:"plan"`
	Stage   Stage  `json:"stage"`
	Started string `json:"started"`

	Step1Boot string `json:"step1_boot,omitempty"`

	Before map[string]UnitState `json:"before,omitempty"`
	Aside  []Aside              `json:"aside,omitempty"`

	Done []Mark `json:"done,omitempty"`

	Failed []string `json:"failed,omitempty"`

	Backup string `json:"backup,omitempty"`

	Residue []string `json:"residue,omitempty"`
}

type PendingOp struct {
	ItemID string
	Op     Op
	Key    string
}

func (j Journal) items() []Item {
	items := slices.Clone(j.Plan.Items)
	slices.SortStableFunc(items, func(x, y Item) int {
		if x.Order != y.Order {
			return x.Order - y.Order
		}
		return strings.Compare(x.ID, y.ID)
	})
	return items
}

func (j Journal) Step1() []PendingOp {
	var out []PendingOp
	for _, it := range j.items() {
		for _, op := range it.Step1 {
			out = append(out, PendingOp{ItemID: it.ID, Op: op})
		}
	}
	return out
}

func (j Journal) Undo(bootID string) []PendingOp {
	if j.Step1Boot != "" && j.Step1Boot != bootID {
		return nil
	}
	var out []PendingOp
	for _, it := range j.items() {
		for _, op := range it.Undo {
			out = append(out, PendingOp{ItemID: it.ID, Op: op})
		}
	}
	return out
}

func (j Journal) mark(key string) (Mark, bool) {
	i := slices.IndexFunc(j.Done, func(m Mark) bool { return m.Key == key })
	if i < 0 {
		return Mark{}, false
	}
	return j.Done[i], true
}

func (j Journal) Pending(bootID string) []PendingOp {
	var out []PendingOp
	for _, it := range j.items() {
		keys := make([]string, len(it.Step3))
		complete := true
		for i, op := range it.Step3 {
			keys[i] = OpKey(it.ID, i, op)
			if _, ok := j.mark(keys[i]); !ok {
				complete = false
			}
		}
		if complete {
			continue
		}
		for i, op := range it.Step3 {
			if m, ok := j.mark(keys[i]); ok && (m.Boot == bootID || !op.temporary()) {
				continue
			}
			out = append(out, PendingOp{ItemID: it.ID, Op: op, Key: keys[i]})
			if slices.Contains(j.Failed, keys[i]) {
				break
			}
		}
	}
	return out
}

func (j Journal) DHCPPending(bootID string) bool {
	retires := map[string]bool{}
	for _, it := range j.Plan.Items {
		if it.RetiresDHCP() {
			retires[it.ID] = true
		}
	}
	return slices.ContainsFunc(j.Pending(bootID), func(p PendingOp) bool { return retires[p.ItemID] })
}

func (j *Journal) Record(key, bootID string, err error) {
	if err != nil {
		if !slices.Contains(j.Failed, key) {
			j.Failed = append(j.Failed, key)
		}
		return
	}
	j.Failed = slices.DeleteFunc(j.Failed, func(k string) bool { return k == key })
	j.Done = slices.DeleteFunc(j.Done, func(m Mark) bool { return m.Key == key })
	j.Done = append(j.Done, Mark{Key: key, Boot: bootID})
}

func (j *Journal) Finish(bootID string, exec func(PendingOp) error, save func(Journal) error) (bool, error) {
	stuck := map[string]bool{}
	for {

		i := slices.IndexFunc(j.Pending(bootID), func(p PendingOp) bool { return !stuck[p.ItemID] })
		if i < 0 {
			break
		}
		p := j.Pending(bootID)[i]
		err := exec(p)
		j.Record(p.Key, bootID, err)
		if serr := save(*j); serr != nil {
			return false, serr
		}
		if err != nil {
			stuck[p.ItemID] = true
		}
	}
	return len(j.Pending(bootID)) == 0, nil
}

func (j Journal) check() error {
	if !slices.Contains(stages, j.Stage) {
		return fmt.Errorf("незнакомый этап захвата %q", j.Stage)
	}
	if len(j.Plan.Digest) != sha256.Size*2 || len(j.Plan.Items) == 0 {
		return errors.New("журнал захвата без плана")
	}
	seen := map[string]bool{}
	for _, it := range j.Plan.Items {
		switch {
		case it.ID == "" || seen[it.ID]:
			return fmt.Errorf("пункт %q в плане журнала пустой или повторяется", it.ID)
		case it.Locked:
			return fmt.Errorf("пункт %q заперт: его панель не трогает", it.ID)
		}
		seen[it.ID] = true
		for _, ops := range [][]Op{it.Step1, it.Step3, it.Undo} {
			for _, op := range ops {
				if err := op.Valid(); err != nil {
					return fmt.Errorf("пункт %q: %w", it.ID, err)
				}
			}
		}
	}
	return nil
}

var stages = []Stage{StageWindow, StageFinishing, StageDone, StagePartial}

func ParseJournal(data []byte) (Journal, error) {
	var head struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return Journal{}, fmt.Errorf("журнал захвата не читается: %w", err)
	}
	if head.Schema != JournalSchema {
		return Journal{}, fmt.Errorf("журнал захвата другой версии: %d, ожидали %d", head.Schema, JournalSchema)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var j Journal
	if err := dec.Decode(&j); err != nil {
		return Journal{}, fmt.Errorf("журнал захвата не читается: %w", err)
	}
	if err := j.check(); err != nil {
		return Journal{}, err
	}
	return j, nil
}

func (j Journal) Marshal() ([]byte, error) {
	switch {
	case j.Schema == 0:
		j.Schema = JournalSchema
	case j.Schema != JournalSchema:
		return nil, fmt.Errorf("журнал захвата другой версии: %d", j.Schema)
	}
	if err := j.check(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
