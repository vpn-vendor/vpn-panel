package metrics

import (
	"errors"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/diskstat"
	"github.com/vpn-vendor/vpn-panel-core/internal/procstat"
	"github.com/vpn-vendor/vpn-panel-core/internal/sysinfo"
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
	RowMemCache    = "mem.cache"
	RowMemSwap     = "mem.swap"
	RowDiskUsed    = "disk.used"
	RowDiskBusy    = "disk.busy"
	RowCPUTemp     = "temp.cpu"
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

type diskReader struct {
	dataDir string
	prev    map[string]uint64
	at      time.Time
}

func (d *diskReader) read() (map[string]float64, error) {
	out := map[string]float64{}
	var firstErr error
	if space, err := diskstat.Usage(d.dataDir); err == nil && space.Total > 0 && space.AvailUnpriv <= space.Total {

		out[RowDiskUsed] = 100 * float64(space.Total-space.AvailUnpriv) / float64(space.Total)
	} else if err != nil {
		firstErr = err
	}
	var names []string
	for _, disk := range sysinfo.Read().Disks {
		names = append(names, disk.Name)
	}
	if cur, err := procstat.ReadDiskTicks(names); err == nil {
		now := time.Now()
		if v, ok := procstat.DiskBusyPercent(d.prev, cur, float64(now.Sub(d.at).Milliseconds())); ok {
			out[RowDiskBusy] = v
		}
		d.prev, d.at = cur, now
	} else if firstErr == nil {
		firstErr = err
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func Sources(dataDir string, links *LinkSource, qos *QoSSource, extra ...Source) []Source {
	cpu := &cpuReader{}
	disk := &diskReader{dataDir: dataDir}
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
		{Name: "proc.mem", Title: "Память", Rows: []string{RowMemUsed, RowMemCache, RowMemSwap},
			Persist: true, Depends: "кольцо и график «Оперативная память»",
			Read: func() (map[string]float64, error) {
				m, err := procstat.ReadMemInfo()
				if err != nil {
					return nil, err
				}
				out := map[string]float64{RowMemUsed: m.UsedPercent(), RowMemCache: m.CachePercent()}
				if v, ok := m.SwapPercent(); ok {
					out[RowMemSwap] = v
				}
				return out, nil
			}},
		{Name: "disk", Title: "Диск", Rows: []string{RowDiskUsed, RowDiskBusy},
			Persist: true, Depends: "кольцо «Диск» и график «Нагрузка диска»",
			Read: disk.read},
		{Name: "sensor.temp", Title: "Температура процессора", Rows: []string{RowCPUTemp},
			Persist: true, Depends: "кольцо «Температура»",
			Read: func() (map[string]float64, error) {

				if t, ok := procstat.ReadCPUTemp(); ok {
					return map[string]float64{RowCPUTemp: t.Cur}, nil
				}
				return map[string]float64{}, nil
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
