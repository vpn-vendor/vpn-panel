package sntp

import (
	"encoding/binary"
	"fmt"
	"time"
)

const PacketSize = 48

const unixEpochOffset = 2208988800

func Request() []byte {
	b := make([]byte, PacketSize)

	b[0] = 0<<6 | 4<<3 | 3
	return b
}

func Offset(resp []byte, t1, t4 time.Time) (time.Duration, error) {
	if len(resp) < PacketSize {
		return 0, fmt.Errorf("ответ службы времени короче положенного")
	}
	li := resp[0] >> 6
	mode := resp[0] & 0x07
	stratum := resp[1]
	switch {
	case li == 3:

		return 0, fmt.Errorf("сервер времени не синхронизирован")
	case mode != 4:
		return 0, fmt.Errorf("это не ответ службы времени")
	case stratum == 0 || stratum > 15:

		return 0, fmt.Errorf("сервер времени отказал в обслуживании")
	}

	t2 := timestampAt(resp, 32)
	t3 := timestampAt(resp, 40)
	if t2.IsZero() || t3.IsZero() {
		return 0, fmt.Errorf("ответ службы времени пуст")
	}
	return (t2.Sub(t1) + t3.Sub(t4)) / 2, nil
}

func timestampAt(b []byte, off int) time.Time {
	secs := binary.BigEndian.Uint32(b[off : off+4])
	frac := binary.BigEndian.Uint32(b[off+4 : off+8])
	if secs == 0 && frac == 0 {
		return time.Time{}
	}

	unix := int64(secs) - unixEpochOffset
	if secs < 2208988800 {
		unix = int64(secs) + 4294967296 - unixEpochOffset
	}
	nsec := int64(float64(frac) / (1 << 32) * 1e9)
	return time.Unix(unix, nsec)
}

var Servers = []string{
	"162.159.200.1",
	"162.159.200.123",
	"216.239.35.0",
	"216.239.35.4",
}

const Suspicious = 5 * time.Minute

const Negligible = 2 * time.Second
