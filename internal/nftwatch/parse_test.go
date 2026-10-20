package nftwatch

import (
	"encoding/binary"
	"slices"
	"testing"
)

const (
	tNewTable = 10 << 8
	tDelTable = 10<<8 | 2
	tNewChain = 10<<8 | 3
	tNewRule  = 10<<8 | 6
	tNewGen   = 10<<8 | 15
	tGetGen   = 10<<8 | 16
	tCtNew    = 1 << 8
	tNoop     = 1
	tDone     = 3

	aGenID   = 1
	aGenPID  = 2
	aGenName = 3

	fNetByteorder = 0x4000
)

func be32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func cstr(s string) []byte { return append([]byte(s), 0) }

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func pad(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func rawAttr(typ uint16, val []byte) []byte {
	b := binary.NativeEndian.AppendUint16(nil, uint16(4+len(val))) //nolint:gosec
	b = binary.NativeEndian.AppendUint16(b, typ)
	return append(b, val...)
}

func attr(typ uint16, val []byte) []byte { return pad(rawAttr(typ, val)) }

func rawMsg(typ uint16, body ...[]byte) []byte {

	payload := cat(append([][]byte{{0, 0, 0, 8}}, body...)...)
	b := binary.NativeEndian.AppendUint32(nil, uint32(16+len(payload))) //nolint:gosec
	b = binary.NativeEndian.AppendUint16(b, typ)
	b = binary.NativeEndian.AppendUint16(b, 0)
	b = binary.NativeEndian.AppendUint32(b, 1)
	b = binary.NativeEndian.AppendUint32(b, 0)
	return append(b, payload...)
}

func msg(typ uint16, body ...[]byte) []byte { return pad(rawMsg(typ, body...)) }

func header(length uint32, typ uint16) []byte {
	b := binary.NativeEndian.AppendUint32(nil, length)
	b = binary.NativeEndian.AppendUint16(b, typ)
	return append(b, make([]byte, 10)...)
}

func gen(pid uint32, name string) []byte {
	return msg(tNewGen, attr(aGenID, be32(8)), attr(aGenPID, be32(pid)), attr(aGenName, cstr(name)))
}

type parseCase struct {
	name    string
	in      []byte
	want    []Event
	wantErr bool
}

func parseCases() []parseCase {
	nft := Event{PID: 1794, Comm: "nft"}
	return []parseCase{
		{name: "пусто", in: nil},

		{name: "новое поколение: PID в сетевом порядке и имя", in: gen(1794, "nft"), want: []Event{nft}},
		{
			name: "несколько сообщений одной датаграммой",
			in: cat(msg(tNewTable), msg(tNewChain), msg(tNewRule, attr(1, cstr("filter"))),
				gen(1794, "nft"), gen(2001, "iptables-nft")),
			want: []Event{{}, {}, {}, nft, {PID: 2001, Comm: "iptables-nft"}},
		},
		{name: "удаление таблицы без виновника", in: msg(tDelTable), want: []Event{{}}},
		{name: "старое ядро: поколение без процесса", in: msg(tNewGen, attr(aGenID, be32(8))), want: []Event{{}}},

		{
			name: "GETGEN с теми же атрибутами — не новое поколение",
			in:   msg(tGetGen, attr(aGenPID, be32(1794)), attr(aGenName, cstr("nft"))),
			want: []Event{{}},
		},
		{name: "чужая подсистема пропускается", in: cat(msg(tCtNew), gen(1794, "nft")), want: []Event{nft}},
		{name: "служебные сообщения netlink пропускаются", in: cat(msg(tNoop), msg(tDone), gen(1794, "nft")), want: []Event{nft}},
		{
			name: "имя без нуля в конце пропускается, PID остаётся",
			in:   msg(tNewGen, attr(aGenPID, be32(1794)), attr(aGenName, []byte("nft"))),
			want: []Event{{PID: 1794}},
		},
		{
			name: "имя до первого нуля",
			in:   msg(tNewGen, attr(aGenPID, be32(1794)), attr(aGenName, []byte("nf\x00t\x00"))),
			want: []Event{{PID: 1794, Comm: "nf"}},
		},
		{
			name: "PID не четыре байта пропускается, имя остаётся",
			in:   msg(tNewGen, attr(aGenPID, []byte{0, 0, 0, 0, 0, 0, 7, 2}), attr(aGenName, cstr("nft"))),
			want: []Event{{Comm: "nft"}},
		},
		{
			name: "флаг порядка байтов в типе атрибута не мешает",
			in:   msg(tNewGen, attr(aGenPID|fNetByteorder, be32(1794)), attr(aGenName, cstr("nft"))),
			want: []Event{nft},
		},
		{
			name: "NLA_ALIGN: имя 9 байт, за ним выровненный PID",
			in:   msg(tNewGen, attr(aGenName, cstr("iptables")), attr(aGenPID, be32(1794))),
			want: []Event{{PID: 1794, Comm: "iptables"}},
		},

		{
			name:    "NLA_ALIGN: без хвоста выравнивания — ошибка",
			in:      msg(tNewGen, rawAttr(aGenName, cstr("iptables")), attr(aGenPID, be32(1794))),
			wantErr: true,
		},
		{
			name: "последнее сообщение без хвоста выравнивания",
			in:   cat(gen(1, "a"), rawMsg(tNewGen, attr(aGenPID, be32(1794)), rawAttr(aGenName, cstr("nftx")))),
			want: []Event{{PID: 1, Comm: "a"}, {PID: 1794, Comm: "nftx"}},
		},
		{
			name: "NLMSG_ALIGN: невыровненное сообщение, хвост, следующее",
			in:   cat(pad(rawMsg(tNewGen, attr(aGenPID, be32(1794)), rawAttr(aGenName, cstr("nftx")))), gen(2, "b")),
			want: []Event{{PID: 1794, Comm: "nftx"}, {PID: 2, Comm: "b"}},
		},
		{
			name:    "NLMSG_ALIGN: без хвоста выравнивания — ошибка",
			in:      cat(rawMsg(tNewGen, attr(aGenPID, be32(1794)), rawAttr(aGenName, cstr("nftx"))), gen(2, "b")),
			want:    []Event{{PID: 1794, Comm: "nftx"}},
			wantErr: true,
		},
		{
			name:    "усечённое сообщение: события до него остаются",
			in:      cat(msg(tNewTable), gen(1794, "nft")[:30]),
			want:    []Event{{}},
			wantErr: true,
		},
		{name: "усечённый заголовок", in: cat(gen(1794, "nft"), make([]byte, 8)), want: []Event{nft}, wantErr: true},
		{name: "нулевая длина сообщения не зацикливает", in: header(0, tNewGen), wantErr: true},
		{name: "длина меньше заголовка", in: header(8, tNewGen), wantErr: true},
		{name: "сообщение nftables без nfgenmsg", in: header(16, tNewTable), wantErr: true},
		{
			name:    "нулевая длина атрибута не зацикливает",
			in:      msg(tNewGen, []byte{0, 0, aGenPID, 0}, be32(1794)),
			wantErr: true,
		},
		{
			name:    "атрибут длиннее сообщения",
			in:      msg(tNewGen, binary.NativeEndian.AppendUint16(nil, 64), []byte{aGenPID, 0}, be32(1794)),
			wantErr: true,
		},
		{name: "усечённый заголовок атрибута", in: msg(tNewGen, attr(aGenPID, be32(1794)), []byte{8, 0}), wantErr: true},
	}
}

func TestParse(t *testing.T) {
	for _, tc := range parseCases() {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parse(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ошибка %v, ждали ошибку: %v", err, tc.wantErr)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("события %+v, ждали %+v", got, tc.want)
			}
		})
	}
}

func TestParseEveryPrefix(t *testing.T) {
	msgs := [][]byte{msg(tNewTable), gen(1794, "nft"), msg(tNewRule, attr(1, cstr("filter"))), gen(7, "iptables")}
	full := cat(msgs...)
	bounds := map[int]int{0: 0}
	off := 0
	for i, m := range msgs {
		off += len(m)
		bounds[off] = i + 1
	}
	all, err := parse(full)
	if err != nil || len(all) != len(msgs) {
		t.Fatalf("целая датаграмма: %+v %v", all, err)
	}
	for cut := 0; cut <= len(full); cut++ {
		got, err := parse(full[:cut])
		whole, atBound := bounds[cut]
		if atBound != (err == nil) {
			t.Fatalf("обрез %d: ошибка %v, граница сообщения: %v", cut, err, atBound)
		}
		if atBound && !slices.Equal(got, all[:whole]) {
			t.Fatalf("обрез %d: %+v", cut, got)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, tc := range parseCases() {
		f.Add(tc.in)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		evs, err := parse(b)
		for _, e := range evs {
			if e.Overflow || e.PID < 0 {
				t.Fatalf("разбор не выдумывает переполнений и отрицательных PID: %+v", e)
			}
		}
		if err == nil && len(b) > 0 && len(b) < 16 {
			t.Fatalf("%d байт не могут быть целым сообщением", len(b))
		}
	})
}
