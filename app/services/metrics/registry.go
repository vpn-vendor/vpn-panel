package metrics

import (
	"errors"

	"github.com/vpn-vendor/vpn-panel-core/internal/procstat"
)

type Class int

const (
	History Class = iota
	Protection
)

type Source struct {
	Name    string
	Title   string
	Rows    []string
	Persist bool
	Depends string

	Read func() (map[string]float64, error)
}

const (
	RowCPUBusy     = "cpu.busy"
	RowLoad1       = "load1"
	RowPressureCPU = "pressure.cpu"
	RowPressureMem = "pressure.mem"
	RowPressureIO  = "pressure.io"
	RowMemUsed     = "mem.used"
)

type cpuReader struct{ prev procstat.CPUTimes }

func (c *cpuReader) read() (map[string]float64, error) {
	cur, err := procstat.ReadCPU()
	if err != nil {
		return nil, err
	}
	prev := c.prev
	c.prev = cur
	if prev.Total == 0 {
		return map[string]float64{}, nil
	}
	v, ok := procstat.BusyPercent(prev, cur)
	if !ok {
		return map[string]float64{}, nil
	}
	return map[string]float64{RowCPUBusy: v}, nil
}

func Sources(links *LinkSource, qos *QoSSource, extra ...Source) []Source {
	cpu := &cpuReader{}
	out := []Source{
		{Name: "proc.cpu", Title: "Загрузка процессора", Rows: []string{RowCPUBusy, RowLoad1},
			Persist: true, Depends: "график «Нагрузка»",
			Read: func() (map[string]float64, error) {
				out, err := cpu.read()
				if err != nil {
					return nil, err
				}
				if l, err := procstat.ReadLoad1(); err == nil {
					out[RowLoad1] = l
				}
				return out, nil
			}},
		{Name: "proc.pressure", Title: "Давление ресурсов", Rows: []string{RowPressureCPU, RowPressureMem, RowPressureIO},
			Persist: true, Depends: "график «Нагрузка»",
			Read: func() (map[string]float64, error) {
				out := map[string]float64{}
				var firstErr error
				for res, row := range map[string]string{"cpu": RowPressureCPU, "memory": RowPressureMem, "io": RowPressureIO} {
					v, err := procstat.ReadPressureSome(res)
					if err != nil {
						if firstErr == nil {
							firstErr = err
						}
						continue
					}
					out[row] = v
				}
				if len(out) == 0 && firstErr != nil {
					return nil, firstErr
				}
				return out, nil
			}},
		{Name: "proc.mem", Title: "Память", Rows: []string{RowMemUsed},
			Persist: true, Depends: "график «Нагрузка»",
			Read: func() (map[string]float64, error) {
				v, err := procstat.ReadMemUsedPercent()
				if err != nil {
					return nil, err
				}
				return map[string]float64{RowMemUsed: v}, nil
			}},
	}
	if links != nil {
		out = append(out, links.Source())
	}
	if qos != nil {
		out = append(out, qos.Source())
	}
	out = append(out, extra...)
	return out
}

var ErrUnknownSource = errors.New("источник не найден")
