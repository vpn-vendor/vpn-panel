package admission

import "time"

type Class int

const (
	Sheddable Class = iota

	Ordinary

	Critical
)

func (c Class) String() string {
	switch c {
	case Sheddable:
		return "сбрасываемый"
	case Ordinary:
		return "обычный"
	case Critical:
		return "критичный"
	}
	return "неизвестный"
}

type Policy struct {
	Ceiling int

	Reserve int

	ShedCeiling int

	LoopbackCeiling int

	QueueCeiling int

	WaitTarget   time.Duration
	WaitInterval time.Duration

	OrdinaryWait time.Duration
	CriticalWait time.Duration

	SignalEvery time.Duration

	RetryAfter time.Duration
}

const (
	PerCore      = 8
	ReserveShare = 4
	ShedShare    = 2
	LoopShare    = 4
	QueueFactor  = 4
	MinSlots     = 2

	WaitTarget   = 100 * time.Millisecond
	WaitInterval = time.Second
	OrdinaryWait = 5 * time.Second
	CriticalWait = 30 * time.Second
	SignalEvery  = time.Second
	RetryAfter   = 2 * time.Second
)

func Derive(cores int) Policy {
	if cores < 1 {
		cores = 1
	}
	ceiling := PerCore * cores
	return Policy{
		Ceiling:         ceiling,
		Reserve:         max(MinSlots, ceiling/ReserveShare),
		ShedCeiling:     max(MinSlots, ceiling/ShedShare),
		LoopbackCeiling: max(MinSlots, ceiling/LoopShare),
		QueueCeiling:    QueueFactor * ceiling,
		WaitTarget:      WaitTarget,
		WaitInterval:    WaitInterval,
		OrdinaryWait:    OrdinaryWait,
		CriticalWait:    CriticalWait,
		SignalEvery:     SignalEvery,
		RetryAfter:      RetryAfter,
	}
}
