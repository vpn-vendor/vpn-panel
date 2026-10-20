package main

import (
	"encoding/json"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/keagen"
	"github.com/vpn-vendor/vpn-panel-core/internal/legacyvpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/netstatus"
)

func (s *surroundings) applyGuard(lans []string, doomed ...string) *agentrpc.ErrorObject {
	if s == nil {
		return nil
	}
	if run, ok := legacyvpn.Running(s.env.root); ok && run.Changing {
		return agentrpc.Busy(codeLegacyBusy, "старый скрипт vpn.sh сейчас меняет систему — дождитесь, пока он закончит, и примените настройки ещё раз",
			surroundEvery)
	}
	if r, bad := s.dhcpConflict(lans, doomed...); bad {
		return dhcpConflictErr(r)
	}
	return nil
}

func dhcpConflictErr(r foreignDHCP) *agentrpc.ErrorObject {
	return &agentrpc.ErrorObject{Code: codeDHCPForeign, Message: dhcpFoundText(r),
		Data: map[string]any{"recoverable": true, "detail": strings.Join(r.Support, "; ")}}
}

func planLANs(p netplangen.Plan) []string {
	var out []string
	for _, i := range p.Interfaces {
		if i.Role == netplangen.RoleLAN {
			out = append(out, i.Name)
		}
	}
	return out
}

func dhcpPlanLANs(p keagen.Plan) []string {
	out := make([]string, 0, len(p.LANs))
	for _, l := range p.LANs {
		out = append(out, l.Name)
	}
	return out
}

func (s *surroundings) dhcpCheck(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p struct {
		LANs      []string         `json:"lans"`
		PlanCards []string         `json:"plan_cards"`
		Takeover  *takeoverConsent `json:"takeover"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &agentrpc.ErrorObject{Code: agentrpc.CodeInvalidParams,
			Message: "запрос к системной службе составлен неверно — обновите страницу", Data: map[string]any{"recoverable": false}}
	}
	status, err := netstatus.Collect()
	if err != nil {
		return nil, internalErr(errReadInterfaces, true)
	}
	known := map[string]bool{}
	for _, i := range status.Interfaces {
		known[i.Name] = !i.Loopback
	}
	var lans []string
	for _, l := range p.LANs {
		if known[l] {
			lans = append(lans, l)
		}
	}
	sel, rerr := p.Takeover.resolve(s.takeover, lans, p.PlanCards)
	if rerr != nil {
		return nil, rerr
	}
	res := map[string]any{"conflict": false}
	if r, bad := s.dhcpConflict(lans, sel.Doomed()...); bad {
		if r.ownServes(lans) {
			res["warning"] = dhcpNeighbourText(r)
		} else {
			res["conflict"], res["message"] = true, dhcpFoundText(r)
		}
	}
	return res, nil
}
