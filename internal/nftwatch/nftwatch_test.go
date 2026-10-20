package nftwatch

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const wait = 10 * time.Second

var (
	ovf   = Event{Overflow: true}
	agent = Event{PID: 100, Comm: "nft"}
	alien = Event{PID: 200, Comm: "nft"}
	ipt   = Event{PID: 300, Comm: "iptables"}
)

func TestMerge(t *testing.T) {
	cases := []struct {
		name  string
		in    []Event
		limit int
		want  []Event
	}{
		{name: "пусто", limit: 4},
		{name: "только события без виновника — одно", in: []Event{{}, {}, {}}, limit: 4, want: []Event{{}}},
		{name: "событие без виновника лишнее рядом с названным", in: []Event{{}, {}, agent, {}}, limit: 4, want: []Event{agent}},
		{name: "один виновник — одно событие", in: []Event{agent, {}, agent}, limit: 4, want: []Event{agent}},

		{name: "одно имя, разные PID — разные виновники", in: []Event{agent, alien}, limit: 4, want: []Event{agent, alien}},
		{name: "повтор встаёт на место последнего", in: []Event{agent, ipt, agent}, limit: 4, want: []Event{ipt, agent}},
		{name: "переполнения — одно, первым", in: []Event{agent, ovf, {}, ovf}, limit: 4, want: []Event{ovf, agent}},
		{name: "только переполнение", in: []Event{{}, ovf}, limit: 4, want: []Event{ovf}},
		{
			name:  "виновников больше места: старшие уходят в переполнение",
			in:    []Event{{PID: 1}, {PID: 2}, {PID: 3}, {PID: 4}, {PID: 5}},
			limit: 3,
			want:  []Event{ovf, {PID: 4}, {PID: 5}},
		},
		{name: "ровно по месту — без переполнения", in: []Event{{PID: 1}, {PID: 2}, {PID: 3}}, limit: 3, want: []Event{{PID: 1}, {PID: 2}, {PID: 3}}},
		{name: "место на одно событие", in: []Event{agent, ipt}, limit: 1, want: []Event{ovf}},
		{name: "переполнение с виновником внутри одного события делится", in: []Event{{PID: 7, Overflow: true}}, limit: 4, want: []Event{ovf, {PID: 7}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := merge(tc.in, tc.limit)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("%+v, ждали %+v", got, tc.want)
			}
			if len(got) > max(tc.limit, 1) {
				t.Fatalf("%d событий при месте %d", len(got), tc.limit)
			}
		})
	}
}

func TestDeliverFullQueue(t *testing.T) {
	ctx := context.Background()
	out := make(chan Event, 2)
	deliver(ctx, out, []Event{{}})
	deliver(ctx, out, []Event{agent})
	if got := drain(out); !slices.Equal(got, []Event{{}, agent}) {
		t.Fatalf("канал с местом: %+v", got)
	}

	deliver(ctx, out, []Event{agent})
	deliver(ctx, out, []Event{ipt})
	deliver(ctx, out, []Event{{}, agent})
	if got := drain(out); !slices.Equal(got, []Event{ipt, agent}) {
		t.Fatalf("слияние по виновнику: %+v", got)
	}

	deliver(ctx, out, []Event{agent})
	deliver(ctx, out, []Event{ipt})
	deliver(ctx, out, []Event{alien})
	if got := drain(out); !slices.Equal(got, []Event{ovf, alien}) {
		t.Fatalf("потеря виновника — переполнение: %+v", got)
	}
}

func fakeRecv(ctx context.Context, steps ...any) func() ([]byte, error) {
	return func() ([]byte, error) {
		if len(steps) == 0 {
			<-ctx.Done()
			return nil, os.ErrClosed
		}
		s := steps[0]
		steps = steps[1:]
		if err, ok := s.(error); ok {
			return nil, err
		}
		return s.([]byte), nil
	}
}

func collect(t *testing.T, ch <-chan Event, n int) []Event {
	t.Helper()
	var got []Event
	for len(got) < n {
		select {
		case e, ok := <-ch:
			if !ok {
				t.Fatalf("канал закрылся после %+v", got)
			}
			got = append(got, e)
		case <-time.After(wait):
			t.Fatalf("нет события после %+v", got)
		}
	}
	return got
}

func closed(t *testing.T, ch <-chan Event) []Event {
	t.Helper()
	var rest []Event
	deadline := time.After(wait)
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				return rest
			}
			rest = append(rest, e)
		case <-deadline:
			t.Fatalf("канал не закрылся, пришло %+v", rest)
		}
	}
}

func TestLoop(t *testing.T) {
	cases := []struct {
		name   string
		steps  []any
		want   []Event
		cancel bool
	}{
		{name: "поколение", steps: []any{gen(1794, "nft")}, want: []Event{{PID: 1794, Comm: "nft"}}, cancel: true},
		{name: "ENOBUFS — переполнение, чтение идёт дальше", steps: []any{unix.ENOBUFS, gen(5, "x")}, want: []Event{ovf, {PID: 5, Comm: "x"}}, cancel: true},
		{name: "нечитаемое — переполнение", steps: []any{header(0, tNewGen)}, want: []Event{ovf}, cancel: true},
		{name: "отказ сокета без отмены — переполнение и закрытие", steps: []any{unix.EBADF}, want: []Event{ovf}},

		{name: "отмена — без переполнения", cancel: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			out := make(chan Event, queueLen)
			go func() {
				defer close(out)
				loop(ctx, fakeRecv(ctx, tc.steps...), out)
			}()
			got := collect(t, out, len(tc.want))
			if tc.cancel {
				cancel()
			}
			if rest := closed(t, out); len(rest) > 0 {
				t.Fatalf("лишнее: %+v", rest)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("%+v, ждали %+v", got, tc.want)
			}
		})
	}
}

func TestWatchSocketpair(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	peer := fds[1]
	defer func() { _ = unix.Close(peer) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := watch(ctx, fds[0])
	if err != nil {
		t.Fatal(err)
	}
	send := func(b []byte) error { return unix.Sendto(peer, b, unix.MSG_NOSIGNAL, nil) }

	if err := send(gen(1794, "nft")); err != nil {
		t.Fatal(err)
	}
	if got := collect(t, ch, 1); got[0] != (Event{PID: 1794, Comm: "nft"}) {
		t.Fatalf("поколение: %+v", got)
	}

	var big []byte
	for len(big) < 3*os.Getpagesize() {
		big = append(big, msg(tNewRule, attr(1, cstr("filter")))...)
	}
	if err := send(append(big, gen(4242, "iptables")...)); err != nil {
		t.Fatal(err)
	}
	if got := collect(t, ch, 1); got[0] != (Event{PID: 4242, Comm: "iptables"}) {
		t.Fatalf("длинная датаграмма: %+v", got)
	}

	if err := send(header(0, tNewGen)); err != nil {
		t.Fatal(err)
	}
	if got := collect(t, ch, 1); got[0] != ovf {
		t.Fatalf("мусор: %+v", got)
	}

	cancel()
	if rest := closed(t, ch); len(rest) > 0 {
		t.Fatalf("после отмены: %+v", rest)
	}

	if err := send(gen(1, "x")); !errors.Is(err, unix.ECONNREFUSED) {
		t.Fatalf("сокет после отмены не закрыт: %v", err)
	}
}

func TestRecvSkipsUserPorts(t *testing.T) {
	sock := func() int {
		fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_USERSOCK)
		if err != nil {
			t.Skipf("netlink недоступен: %v", err)
		}
		if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
			t.Fatal(err)
		}
		return fd
	}
	fd, forger := sock(), sock()
	defer func() { _ = unix.Close(forger) }()
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "nftables-test")
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	forged := gen(1, "systemd")
	if err := unix.Sendto(forger, forged, 0, sa); err != nil {
		t.Fatal(err)
	}

	type result struct {
		data []byte
		err  error
	}
	res := make(chan result, 1)
	go func() {
		buf := make([]byte, 1)
		data, err := recvDatagram(rc, &buf)
		res <- result{data, err}
	}()
	deadline := time.Now().Add(wait)
	for {
		select {
		case r := <-res:
			t.Fatalf("поддельная датаграмма прочитана: % x %v", r.data, r.err)
		default:
		}
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}} //nolint:gosec
		if n, err := unix.Poll(pfd, 0); err == nil && n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("датаграмму так и не вынули из очереди")
		}
		time.Sleep(time.Millisecond)
	}
	_ = f.Close()
	if r := <-res; r.data != nil || r.err == nil {
		t.Fatalf("после закрытия: % x %v", r.data, r.err)
	}
}

func TestSubscribe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch, err := Subscribe(ctx)
	switch {
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		t.Skipf("нет CAP_NET_ADMIN: %v", err)
	case errors.Is(err, unix.EPROTONOSUPPORT):
		t.Skipf("в ядре нет nfnetlink: %v", err)
	case err != nil:
		t.Fatal(err)
	}
	cancel()
	closed(t, ch)
}
