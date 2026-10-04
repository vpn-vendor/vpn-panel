package main

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpndriver"
)

type secretsV1 struct {
	Version   int               `json:"version"`
	WireGuard map[string]string `json:"wireguard,omitempty"`
	OpenVPN   map[string]string `json:"openvpn,omitempty"`
	PPPoE     *pppoeCredentials `json:"pppoe,omitempty"`
}

func fromV1(raw json.RawMessage) (backupSecrets, error) {
	var v secretsV1
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		return backupSecrets{}, backupfile.ErrMalformed
	}
	out := backupSecrets{Version: secretsVersion, PPPoE: v.PPPoE}
	for proto, texts := range map[vpndriver.Protocol]map[string]string{"wireguard": v.WireGuard, "openvpn": v.OpenVPN} {
		for slug, text := range texts {
			out.Profiles = append(out.Profiles, secretProfile{Protocol: proto, Slug: slug, Text: text})
		}
	}
	sortProfiles(out.Profiles)
	return out, nil
}

func sortProfiles(p []secretProfile) {
	sort.Slice(p, func(i, j int) bool {
		if p[i].Protocol != p[j].Protocol {
			return p[i].Protocol < p[j].Protocol
		}
		return p[i].Slug < p[j].Slug
	})
}
