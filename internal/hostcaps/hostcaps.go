package hostcaps

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

const Schema = 2

type Answer string

const (
	Yes     Answer = "yes"
	No      Answer = "no"
	Unknown Answer = "unknown"
)

type Class string

const (
	ClassGuard Class = "guard"

	ClassFeature Class = "feature"

	ClassComfort Class = "comfort"

	ClassDecision Class = "decision"

	ClassForeign Class = "foreign"
)

const (
	HowCheck    = "check"
	HowControl  = "control"
	HowFailed   = "failed"
	HowBase     = "base"
	HowModprobe = "modprobe"
	HowRun      = "run"
	HowFile     = "file"
	HowSocket   = "socket"
	HowProcess  = "process"
	HowUnit     = "unit"

	HowCounter = "counter"
)

const (
	LevelError = "error"
	LevelWarn  = "warn"
	LevelInfo  = "info"
)

type Fact struct {
	ID     string `json:"id"`
	Class  Class  `json:"class"`
	Answer Answer `json:"answer"`

	Value string `json:"value,omitempty"`
	How   string `json:"how"`

	Consumers []string `json:"consumers,omitempty"`

	Title   string `json:"title"`
	Missing string `json:"missing"`

	Level   string   `json:"level,omitempty"`
	Cards   []string `json:"cards,omitempty"`
	Cause   string   `json:"cause,omitempty"`
	Found   string   `json:"found,omitempty"`
	Support []string `json:"support,omitempty"`

	Reset bool `json:"reset,omitempty"`
}

const CauseLegacy = "legacy"

type Surroundings struct {
	TakenAt  string `json:"taken_at"`
	Settling bool   `json:"settling"`
	Facts    []Fact `json:"facts"`
}

func (s Surroundings) Fact(id string) (Fact, bool) {
	for _, f := range s.Facts {
		if f.ID == id {
			return f, true
		}
	}
	return Fact{}, false
}

type Snapshot struct {
	Schema int `json:"schema"`

	TakenAt string `json:"taken_at"`

	Inputs string `json:"inputs"`

	Digest   string            `json:"digest"`
	Versions map[string]string `json:"versions"`
	Facts    []Fact            `json:"facts"`
}

type Status struct {
	Snapshot

	Probing bool `json:"probing"`
}

func (s Snapshot) Answer(id string) Answer {
	for _, f := range s.Facts {
		if f.ID == id {
			return f.Answer
		}
	}
	return Unknown
}

func (s Snapshot) Value(id string) string {
	for _, f := range s.Facts {
		if f.ID == id && f.Answer == Yes {
			return f.Value
		}
	}
	return ""
}

func (s Snapshot) Unsure() bool {
	for _, f := range s.Facts {
		if f.Answer == Unknown {
			return true
		}
	}
	return false
}

func FactsDigest(facts []Fact) string {
	lines := make([]string, 0, len(facts))
	for _, f := range facts {
		lines = append(lines, f.ID+"="+string(f.Answer)+"|"+f.Value)
	}
	return digest(lines)
}

func SectionDigest(facts []Fact, section string) string {
	var own []Fact
	for _, f := range facts {
		for _, c := range f.Consumers {
			if c == section {
				own = append(own, f)
				break
			}
		}
	}
	return FactsDigest(own)
}

func InputsDigest(versions map[string]string, ids []string) string {
	lines := make([]string, 0, len(versions)+len(ids))
	for k, v := range versions {
		lines = append(lines, "version "+k+"="+v)
	}
	for _, id := range ids {
		lines = append(lines, "fact "+id)
	}
	return digest(append(lines, "schema "+strconv.Itoa(Schema)))
}

func digest(lines []string) string {
	sorted := append([]string(nil), lines...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return hex.EncodeToString(sum[:])
}

type Defect struct {
	ID       string
	Package  string
	Versions string
	Evidence string
	Until    string
}

var Defects []Defect
