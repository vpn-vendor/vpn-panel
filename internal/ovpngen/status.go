package ovpngen

import (
	"net"
	"strconv"
	"strings"
)

type State struct {
	Unix       int64  `json:"unix"`
	Name       string `json:"name"`
	Connected  bool   `json:"connected"`
	LocalIPv4  string `json:"local_ipv4,omitempty"`
	Remote     string `json:"remote,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
}

func ParseState(reply string) (State, bool) {
	for _, line := range strings.Split(reply, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ">") || line == "END" || strings.HasPrefix(line, "SUCCESS") || strings.HasPrefix(line, "ERROR") {
			continue
		}
		f := strings.Split(line, ",")
		if len(f) < 2 {
			continue
		}
		ts, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		st := State{Unix: ts, Name: f[1], Connected: f[1] == "CONNECTED"}
		if len(f) > 3 {
			st.LocalIPv4 = f[3]
		}
		if len(f) > 4 {
			st.Remote = f[4]
		}
		if len(f) > 5 {
			if port, perr := strconv.Atoi(f[5]); perr == nil {
				st.RemotePort = port
			}
		}
		return st, true
	}
	return State{}, false
}

func ParsePushReply(line string) []string {
	i := strings.Index(line, "PUSH_REPLY,")
	if i < 0 {
		return nil
	}
	rest := line[i+len("PUSH_REPLY,"):]
	rest = strings.TrimRight(strings.TrimSpace(rest), "'")
	var out []string
	for _, opt := range strings.Split(rest, ",") {
		if opt = strings.TrimSpace(opt); opt != "" {
			out = append(out, opt)
		}
	}
	return out
}

func PushedRouteGateway(pushed []string) string {
	const prefix = "route-gateway "
	for _, opt := range pushed {
		if !strings.HasPrefix(opt, prefix) {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(opt, prefix))

		if ip := net.ParseIP(val); ip != nil && ip.To4() != nil {
			return ip.String()
		}
		return ""
	}
	return ""
}

var refusedPushPrefixes = []string{
	"redirect-gateway", "route ", "route-ipv6", "dhcp-option", "dns ", "block-outside-dns",
	"ifconfig-ipv6", "compress", "comp-lzo", "fragment",
}

func RefusedPushes(pushed []string) []string {
	var out []string
	for _, opt := range pushed {
		for _, prefix := range refusedPushPrefixes {
			if strings.HasPrefix(opt, prefix) {
				out = append(out, opt)
				break
			}
		}
	}
	return out
}

const (
	PhaseConnecting   = "CONNECTING"
	PhaseWait         = "WAIT"
	PhaseAuth         = "AUTH"
	PhaseGetConfig    = "GET_CONFIG"
	PhaseAssignIP     = "ASSIGN_IP"
	PhaseAddRoutes    = "ADD_ROUTES"
	PhaseConnected    = "CONNECTED"
	PhaseReconnecting = "RECONNECTING"
	PhaseExiting      = "EXITING"
)

const (
	FailNone          = ""
	FailServerSilent  = "server_silent"
	FailTLSVerify     = "tls_verify_failed"
	FailCertRejected  = "cert_rejected"
	FailAfterTLS      = "rejected_after_tls"
	AuthStuckAfterSec = 60

	CertStallSec = 30
)

type Tracker struct {
	Last          State
	LastDesc      string
	LastUnix      int64
	ReachedAuth   bool
	ReachedConfig bool
	Connected     bool

	FailCount    int
	LastFailUnix int64
	LastFailDesc string

	ServerMessage string
	Exited        bool

	FirstUnix int64
	PhaseUnix int64

	AuthUnix int64

	StickyFail string

	countedUnix int64

	attemptAuth, attemptConnected bool
}

func (t *Tracker) Reset() {
	*t = Tracker{
		FailCount:     t.FailCount,
		LastFailUnix:  t.LastFailUnix,
		LastFailDesc:  t.LastFailDesc,
		ServerMessage: t.ServerMessage,
		StickyFail:    t.StickyFail,
		countedUnix:   t.countedUnix,
	}
}

func (t *Tracker) Feed(line string) bool {
	line = strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(line, ">STATE:"):
		return t.feedState(strings.TrimPrefix(line, ">STATE:"))
	case strings.HasPrefix(line, ">LOG:"):

		if i := strings.Index(line, "AUTH_FAILED"); i >= 0 {
			t.ServerMessage = strings.TrimSpace(strings.TrimPrefix(line[i:], "AUTH_FAILED,"))
		}
		return false
	case line == "" || strings.HasPrefix(line, ">") || line == "END" || strings.HasPrefix(line, "SUCCESS") || strings.HasPrefix(line, "ERROR"):
		return false
	}

	if st, ok := ParseState(line); ok {
		return t.apply(st, stateDesc(line))
	}
	return false
}

func (t *Tracker) feedState(payload string) bool {
	st, ok := ParseState(payload)
	if !ok {
		return false
	}
	return t.apply(st, stateDesc(payload))
}

func stateDesc(line string) string {
	f := strings.Split(line, ",")
	if len(f) > 2 {
		return strings.TrimSpace(f[2])
	}
	return ""
}

func (t *Tracker) apply(st State, desc string) bool {
	if t.FirstUnix == 0 {
		t.FirstUnix = st.Unix
	}
	entered := st.Name != t.Last.Name
	if entered {
		t.PhaseUnix = st.Unix
	}
	t.Last, t.LastDesc, t.LastUnix = st, desc, st.Unix
	switch st.Name {
	case PhaseAuth:

		if entered {
			t.AuthUnix = st.Unix
		}
		t.ReachedAuth, t.attemptAuth = true, true
	case PhaseGetConfig, PhaseAssignIP, PhaseAddRoutes:
		t.ReachedAuth, t.ReachedConfig, t.attemptAuth = true, true, true
	case PhaseConnected:
		t.ReachedAuth, t.ReachedConfig, t.Connected = true, true, true
		t.attemptAuth, t.attemptConnected = true, true
		t.FailCount, t.LastFailDesc, t.ServerMessage, t.StickyFail = 0, "", "", ""
	case PhaseReconnecting:
		t.endAttempt(st.Unix, desc)
	case PhaseExiting:
		t.Exited = true
		t.endAttempt(st.Unix, desc)
	}

	if c := t.classify(st.Unix); c != FailNone {
		t.StickyFail = c
	}
	return true
}

func (t *Tracker) endAttempt(unix int64, desc string) {
	if t.attemptAuth && !t.attemptConnected {
		t.countFail(unix, desc)
	}
	t.attemptAuth, t.attemptConnected = false, false
}

func (t *Tracker) countFail(unix int64, desc string) {
	t.LastFailUnix, t.LastFailDesc = unix, desc
	if unix > t.countedUnix {
		t.FailCount++
		t.countedUnix = unix
	}
}

func (t *Tracker) Failure(now int64) string {
	if t.Connected && !t.Exited && t.Last.Name == PhaseConnected {
		return FailNone
	}
	if c := t.classify(now); c != FailNone {
		return c
	}
	return t.StickyFail
}

func (t *Tracker) classify(now int64) string {
	stuck := func(since int64) bool { return since > 0 && now-since >= AuthStuckAfterSec }
	ended := t.Exited || t.Last.Name == PhaseReconnecting
	switch {
	case t.Connected:
		return FailNone
	case t.ReachedConfig && ended:
		return FailAfterTLS
	case t.ReachedAuth && ended && t.LastDesc == "tls-error":

		if t.AuthUnix > 0 && t.LastUnix-t.AuthUnix >= CertStallSec {
			return FailCertRejected
		}
		return FailTLSVerify
	case t.ReachedAuth && t.Last.Name == PhaseAuth && stuck(t.PhaseUnix):
		return FailCertRejected
	case !t.ReachedAuth && ended && t.LastDesc == "tls-error":
		return FailServerSilent
	case !t.ReachedAuth && stuck(t.FirstUnix):
		return FailServerSilent
	}
	return FailNone
}
