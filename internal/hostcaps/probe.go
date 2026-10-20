package hostcaps

import "errors"

type Option[C any] struct {
	ID        string
	Consumers []string
	Enable    func(*C)

	Title, Missing string
}

func Caps[C any](s Snapshot, opts []Option[C]) C {
	var c C
	for _, o := range opts {
		if s.Answer(o.ID) == Yes {
			o.Enable(&c)
		}
	}
	return c
}

func IDs[C any](opts []Option[C]) []string {
	ids := make([]string, 0, len(opts))
	for _, o := range opts {
		ids = append(ids, o.ID)
	}
	return ids
}

type Rejected struct{ Detail string }

func (r *Rejected) Error() string { return "конфиг не принят: " + r.Detail }

func IsRejected(err error) bool {
	var r *Rejected
	return errors.As(err, &r)
}

type Program[C any] struct {
	Render func(C) ([]byte, error)

	Check func([]byte) error

	Spoil func([]byte) []byte

	Base                   string
	BaseClass              Class
	BaseConsumers          []string
	BaseTitle, BaseMissing string
	Options                []Option[C]
}

func Probe[C any](p Program[C]) []Fact {
	baseAnswer, baseHow, optHow := Unknown, HowFailed, HowFailed
	var zero C
	if base, err := p.Render(zero); err == nil {
		baseErr := p.Check(base)
		spoilErr := p.Check(p.Spoil(base))
		switch {
		case spoilErr == nil:
			baseHow, optHow = HowControl, HowControl
		case !IsRejected(spoilErr) || (baseErr != nil && !IsRejected(baseErr)):

		case baseErr != nil:
			baseAnswer, baseHow, optHow = No, HowCheck, HowBase
		default:
			baseAnswer, baseHow = Yes, HowCheck
		}
	}

	var facts []Fact
	if p.Base != "" {
		facts = append(facts, Fact{ID: p.Base, Class: p.BaseClass, Answer: baseAnswer, How: baseHow,
			Consumers: p.BaseConsumers, Title: p.BaseTitle, Missing: p.BaseMissing})
	}
	for _, o := range p.Options {
		f := Fact{ID: o.ID, Class: ClassFeature, Answer: Unknown, How: optHow, Consumers: o.Consumers,
			Title: o.Title, Missing: o.Missing}
		if baseAnswer == Yes {
			f.Answer, f.How = probeOption(p, o)
		}
		facts = append(facts, f)
	}
	return facts
}

func probeOption[C any](p Program[C], o Option[C]) (Answer, string) {
	var c C
	o.Enable(&c)
	cfg, err := p.Render(c)
	if err != nil {
		return Unknown, HowFailed
	}
	switch err := p.Check(cfg); {
	case err == nil:
		return Yes, HowCheck
	case IsRejected(err):
		return No, HowCheck
	default:
		return Unknown, HowFailed
	}
}
