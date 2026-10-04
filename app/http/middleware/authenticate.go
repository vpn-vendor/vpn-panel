package middleware

import (
	"net"
	"strings"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/services/auth"
)

const CtxDevice = "auth.device"

var openPrefixes = []string{
	"/login",
	"/setup",
	"/health",
	"/public/",

	"/whoami",
	"/lantest",
}

type Authenticate struct {
	service *auth.Service
}

func NewAuthenticate() *Authenticate {
	return &Authenticate{service: auth.New()}
}

func (m *Authenticate) Signature() string { return "vpn-panel:authenticate" }

func (m *Authenticate) Handle(ctx contractshttp.Context) {
	path := ctx.Request().Path()

	if path == "/" && IsShortHost(ctx.Request().Host()) {
		ctx.Request().Next()
		return
	}
	for _, p := range openPrefixes {
		if path == strings.TrimSuffix(p, "/") || strings.HasPrefix(path, p) {
			ctx.Request().Next()
			return
		}
	}

	token := ctx.Request().Cookie(auth.DeviceCookie)
	device, err := m.service.ValidateDevice(token, ctx.Request().Ip())
	if err != nil {

		target := "/login"
		if !m.service.HasUsers() {
			target = "/setup"
		}
		_ = ctx.Response().Redirect(contractshttp.StatusFound, target).Abort()
		return
	}

	ctx.WithValue(CtxDevice, device)
	ctx.Request().Next()
}

func IsShortHost(host string) bool {
	h := strings.ToLower(host)
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h, "]") {
		h = h[:i]
	}
	return h == "pc" || h == "pc.vpn.lan"
}

func IsLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}
