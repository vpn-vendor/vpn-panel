package middleware

import (
	contractshttp "github.com/goravel/framework/contracts/http"
)

const csp = "default-src 'none'; " +
	"script-src 'self'; " +
	"style-src 'self'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'none'"

type SecurityHeaders struct{}

func NewSecurityHeaders() *SecurityHeaders { return &SecurityHeaders{} }

func (m *SecurityHeaders) Signature() string { return "vpn-panel:security_headers" }

func (m *SecurityHeaders) Handle(ctx contractshttp.Context) {

	resp := ctx.Response()
	resp.Header("Content-Security-Policy", csp)
	resp.Header("X-Content-Type-Options", "nosniff")
	resp.Header("Referrer-Policy", "no-referrer")
	resp.Header("X-Frame-Options", "DENY")
	ctx.Request().Next()
}
