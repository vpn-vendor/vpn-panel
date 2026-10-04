package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/url"
	"strings"

	contractshttp "github.com/goravel/framework/contracts/http"
)

const (
	CsrfCookie = "vp_csrf"
	CsrfField  = "_csrf"

	CtxCsrf = "csrf.token"
)

type CsrfGuard struct{}

func NewCsrfGuard() *CsrfGuard { return &CsrfGuard{} }

func (m *CsrfGuard) Signature() string { return "vpn-panel:csrf_guard" }

func (m *CsrfGuard) Handle(ctx contractshttp.Context) {
	token := ctx.Request().Cookie(CsrfCookie)

	method := ctx.Request().Method()
	if method == contractshttp.MethodGet || method == contractshttp.MethodHead {
		if len(token) != 64 {
			token = newCsrfToken()

			ctx.Response().Cookie(contractshttp.Cookie{
				Name: CsrfCookie, Value: token, Path: "/",
				Secure: true, HttpOnly: true, SameSite: "Strict",
			})
		}
		ctx.WithValue(CtxCsrf, token)
		ctx.Request().Next()
		return
	}

	form := ctx.Request().Input(CsrfField)
	if len(token) != 64 || subtle.ConstantTimeCompare([]byte(form), []byte(token)) != 1 {
		abortCsrf(ctx)
		return
	}

	ctx.WithValue(CtxCsrf, token)

	if origin := ctx.Request().Header("Origin"); origin != "" && origin != "null" {
		if !sameHost(origin, ctx.Request().Host()) {
			abortCsrf(ctx)
			return
		}
	}
	ctx.Request().Next()
}

func abortCsrf(ctx contractshttp.Context) {
	const page = `<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">` +
		`<title>Запрос отклонён</title>` +
		`<link rel="stylesheet" href="/public/css/app.css">` +
		`<link rel="icon" href="data:,"></head>` +
		`<body><div class="auth-wrap"><div class="auth-card"><h1>Запрос отклонён</h1>` +
		`<p>Похоже, страница устарела или запрос пришёл с другого сайта.</p>` +
		`<p>Вернитесь назад в браузере, обновите страницу (Ctrl+F5) и попробуйте ещё раз.</p>` +
		`</div></div></body></html>`
	_ = ctx.Response().Data(contractshttp.StatusForbidden, "text/html; charset=utf-8", []byte(page)).Abort()
}

func newCsrfToken() string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return ""
	}
	return hex.EncodeToString(raw)
}

func sameHost(origin, requestHost string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	reqHost := requestHost
	if h, _, splitErr := net.SplitHostPort(requestHost); splitErr == nil {
		reqHost = h
	}
	return strings.EqualFold(parsed.Hostname(), reqHost)
}
