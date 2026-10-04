package metrics

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math"
	"sort"
)

var fileMagic = [4]byte{'V', 'P', 'M', 'T'}

const (
	FileVersion = 1
	headerLen   = 4 + 2 + 2 + 4 + 4 + 4

	PersistFrom = 1
)

var ErrBadFile = errors.New("файл показателей не распознан")

func Save(w io.Writer, rows map[string]*Series) error {
	names := make([]string, 0, len(rows))
	for n := range rows {
		names = append(names, n)
	}
	sort.Strings(names)
	var body bytes.Buffer
	count := uint32(0)
	for _, name := range names {
		s := rows[name]
		if len(name) == 0 || len(name) > 255 {
			continue
		}
		for i := PersistFrom; i < Tiers; i++ {
			r := &s.rings[i]
			body.WriteByte(byte(len(name))) //nolint:gosec
			body.WriteString(name)
			body.WriteByte(byte(i))
			bin(&body, uint32(r.stepSec()), uint32(len(r.avg)), uint32(r.head), uint32(r.count)) //nolint:gosec
			bin(&body, r.last)
			bin(&body, r.avg)
			if r.lo != nil {
				bin(&body, r.lo, r.hi)
			}
			count++
		}
	}
	var h bytes.Buffer
	h.Write(fileMagic[:])
	bin(&h, uint16(FileVersion), uint16(0), count, uint32(body.Len()), crc32.ChecksumIEEE(body.Bytes())) //nolint:gosec
	if _, err := w.Write(h.Bytes()); err != nil {
		return err
	}
	_, err := w.Write(body.Bytes())
	return err
}

func bin(w io.Writer, vs ...any) {
	for _, v := range vs {
		_ = binary.Write(w, binary.LittleEndian, v)
	}
}

func Load(r io.Reader, rows map[string]*Series) (int, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return 0, err
	}
	if len(data) < headerLen || !bytes.Equal(data[:4], fileMagic[:]) {
		return 0, ErrBadFile
	}
	hdr := bytes.NewReader(data[4:headerLen])
	var version, reserved uint16
	var count, bodyLen, sum uint32
	_ = binary.Read(hdr, binary.LittleEndian, &version)
	_ = binary.Read(hdr, binary.LittleEndian, &reserved)
	_ = binary.Read(hdr, binary.LittleEndian, &count)
	_ = binary.Read(hdr, binary.LittleEndian, &bodyLen)
	_ = binary.Read(hdr, binary.LittleEndian, &sum)
	if version != FileVersion || int(bodyLen) != len(data)-headerLen {
		return 0, ErrBadFile
	}
	body := data[headerLen:]
	if crc32.ChecksumIEEE(body) != sum {
		return 0, ErrBadFile
	}
	rd := bytes.NewReader(body)
	restored := 0
	for i := uint32(0); i < count; i++ {
		var nameLen uint8
		if binary.Read(rd, binary.LittleEndian, &nameLen) != nil {
			return restored, ErrBadFile
		}
		name := make([]byte, nameLen)
		if _, err := io.ReadFull(rd, name); err != nil {
			return restored, ErrBadFile
		}
		var tier uint8
		var step, length, head, cnt uint32
		var last int64
		if binary.Read(rd, binary.LittleEndian, &tier) != nil ||
			binary.Read(rd, binary.LittleEndian, &step) != nil ||
			binary.Read(rd, binary.LittleEndian, &length) != nil ||
			binary.Read(rd, binary.LittleEndian, &head) != nil ||
			binary.Read(rd, binary.LittleEndian, &cnt) != nil ||
			binary.Read(rd, binary.LittleEndian, &last) != nil {
			return restored, ErrBadFile
		}
		agg := int(tier) >= 1
		arrays := 1
		if agg {
			arrays = 3
		}
		vals := make([]float64, int(length)*arrays)
		if binary.Read(rd, binary.LittleEndian, vals) != nil {
			return restored, ErrBadFile
		}
		s, ok := rows[string(name)]
		if !ok || int(tier) >= Tiers || int(tier) < PersistFrom {
			continue
		}
		ring := &s.rings[tier]
		if int(length) != len(ring.avg) || int64(step) != ring.stepSec() || int(head) >= len(ring.avg) || int(cnt) > len(ring.avg) {
			continue
		}
		copy(ring.avg, vals[:length])
		if agg {
			copy(ring.lo, vals[length:2*length])
			copy(ring.hi, vals[2*length:])
		}
		ring.head, ring.count, ring.last = int(head), int(cnt), last
		for j := range ring.avg {
			if math.IsInf(ring.avg[j], 0) {
				ring.clear(j)
			}
		}
		restored++
	}
	return restored, nil
}
