package controllers

import (
	"encoding/base64"

	contractshttp "github.com/goravel/framework/contracts/http"
)

const (
	flashCode   = "vp_flash_code"
	flashError  = "vp_flash_err"
	flashReturn = "vp_flash_back"

	flashDone = "vp_flash_done"
)

func setFlash(ctx contractshttp.Context, name, value string) {
	ctx.Response().Cookie(contractshttp.Cookie{
		Name:     name,
		Value:    base64.RawURLEncoding.EncodeToString([]byte(value)),
		Path:     "/",
		MaxAge:   60,
		Secure:   true,
		HttpOnly: true,
		SameSite: "Strict",
	})
}

func takeFlash(ctx contractshttp.Context, name string) string {
	raw := ctx.Request().Cookie(name)
	if raw == "" {
		return ""
	}
	ctx.Response().Cookie(contractshttp.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: "Strict",
	})
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return ""
	}
	return string(decoded)
}
