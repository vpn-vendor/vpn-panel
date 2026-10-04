package controllers

import "github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"

func eventTitle(event string) string { return securitylog.Title(event) }
