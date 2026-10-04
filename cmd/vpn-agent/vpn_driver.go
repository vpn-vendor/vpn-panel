package main

import (
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

type tunnelFacts struct {
	Present bool

	Connected bool

	AgeSec  int64
	RxBytes int64
	TxBytes int64

	PayloadRx int64
	PayloadTx int64

	Endpoint string

	TunnelIPv4 string

	PeerIPv4 string

	KernelDataPlane bool

	ServicesMissing bool

	Pushed []string

	ProcRunning   bool
	ProcState     string
	FailReason    string
	FailCount     int
	LastFailUnix  int64
	ServerMessage string
}

type upRequest struct {
	Slug string
	MTU  int
	Mark int

	NewIntent bool
}

type upResult struct {
	Changed      bool
	EndpointIP   string
	EndpointPort int
	Transport    string

	Overhead int
}

type tunnelDriver interface {
	protocol() vpndriver.Protocol
	iface() string

	journal() []string
	passport(transport string) vpndriver.Passport

	importProfile(slug, text string) (vpndriver.Meta, []string, *agentrpc.ErrorObject)
	listProfiles() []string

	profileText(slug string) (string, error)

	removeProfile(slug string, active bool) error

	up(req upRequest) (upResult, *agentrpc.ErrorObject)

	down() bool
	present() bool
	facts() tunnelFacts

	ensureRoutes() error
}

type unknownDriver struct{ p vpndriver.Protocol }

func (d unknownDriver) refuse() *agentrpc.ErrorObject {
	return &agentrpc.ErrorObject{Code: codeVPNUp,
		Message: "протокол профиля «" + string(d.p) + "» этой версии панели неизвестен — обновите панель или выберите другой профиль",
		Data:    map[string]any{"recoverable": false}}
}
func (d unknownDriver) protocol() vpndriver.Protocol { return d.p }

func (d unknownDriver) iface() string { return "vpn-unknown" }

func (d unknownDriver) journal() []string { return nil }
func (d unknownDriver) passport(t string) vpndriver.Passport {
	return vpndriver.Passport{Protocol: d.p, Transport: t}
}
func (d unknownDriver) importProfile(string, string) (vpndriver.Meta, []string, *agentrpc.ErrorObject) {
	return vpndriver.Meta{}, nil, d.refuse()
}
func (d unknownDriver) listProfiles() []string                         { return nil }
func (d unknownDriver) profileText(string) (string, error)             { return "", d.refuse() }
func (d unknownDriver) removeProfile(string, bool) error               { return d.refuse() }
func (d unknownDriver) up(upRequest) (upResult, *agentrpc.ErrorObject) { return upResult{}, d.refuse() }
func (d unknownDriver) down() bool                                     { return false }
func (d unknownDriver) present() bool                                  { return false }
func (d unknownDriver) facts() tunnelFacts                             { return tunnelFacts{} }
func (d unknownDriver) ensureRoutes() error                            { return d.refuse() }

type pausable interface {
	pause(reason string) error

	resume() error
}

type eventful interface {
	events() <-chan struct{}
}
