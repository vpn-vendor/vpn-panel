package main

import (
	"encoding/json"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/vpn-vendor/vpn-panel-core/internal/nftgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/qosgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/unboundgen"
)

const netFactsFile = "/etc/vpn-panel/net-facts.json"

type netFacts struct {
	Firewall *nftgen.FirewallPlan `json:"firewall,omitempty"`
	DNS      *unboundgen.Plan     `json:"dns,omitempty"`
	QoS      *qosgen.Plan         `json:"qos,omitempty"`
}

type modeOverlay struct {
	Tunnel    *nftgen.FirewallTunnel
	DNSOut    string
	QoSTunnel string
}

type modeComposer struct {
	mu      sync.Mutex
	path    string
	facts   netFacts
	overlay modeOverlay

	sealed bool

	onFirewallFacts func(nftgen.FirewallPlan)

	onUnbound func()
}

func newModeComposer() *modeComposer { return &modeComposer{path: netFactsFile} }

func (c *modeComposer) load() {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := json.Unmarshal(data, &c.facts); err != nil {
		log.Printf("compose: network facts unreadable, will be rebuilt: %v", err)
		c.facts = netFacts{}
	}
}

func (c *modeComposer) persist() {
	data, err := json.Marshal(c.facts)
	if err != nil {
		return
	}
	err = durable.MkdirAll(filepath.Dir(c.path), 0o755)
	if err == nil {
		err = durable.Write(c.path, data, 0o600)
	}
	if err != nil {
		log.Printf("compose: network facts not saved: %v", err)
	}
}

func (c *modeComposer) SetFirewallFacts(p nftgen.FirewallPlan) {
	p.Tunnel = nil
	c.mu.Lock()
	c.facts.Firewall = &p
	c.persist()
	hook := c.onFirewallFacts
	c.mu.Unlock()
	if hook != nil {
		hook(p)
	}
}

func (c *modeComposer) FirewallFacts() (nftgen.FirewallPlan, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.facts.Firewall == nil {
		return nftgen.FirewallPlan{}, false
	}
	return *c.facts.Firewall, true
}

func (c *modeComposer) SetDNSFacts(p unboundgen.Plan) {
	p.OutgoingAddress = ""
	c.mu.Lock()
	defer c.mu.Unlock()
	c.facts.DNS = &p
	c.persist()
}

func (c *modeComposer) SetQoSFacts(p qosgen.Plan) {
	p.Tunnel = ""
	c.mu.Lock()
	defer c.mu.Unlock()
	c.facts.QoS = &p
	c.persist()
}

func (c *modeComposer) FirewallWANs() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.facts.Firewall == nil {
		return nil
	}
	return append([]string(nil), c.facts.Firewall.WANs...)
}

func (c *modeComposer) SetOverlay(o modeOverlay) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.overlay = o
}

func (c *modeComposer) Seal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sealed = true
}

func (c *modeComposer) Unseal() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	was := c.sealed
	c.sealed = false
	return was
}

func (c *modeComposer) Sealed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sealed
}

func (c *modeComposer) Firewall(fallback nftgen.FirewallPlan) nftgen.FirewallPlan {
	c.mu.Lock()
	created := c.facts.Firewall == nil
	if created {
		base := fallback
		base.Tunnel = nil
		c.facts.Firewall = &base
		c.persist()
	}
	facts := *c.facts.Firewall
	out := facts
	out.Tunnel = c.overlay.Tunnel
	hook := c.onFirewallFacts
	c.mu.Unlock()
	if created && hook != nil {
		hook(facts)
	}
	return out
}

func (c *modeComposer) FirewallWith(facts nftgen.FirewallPlan) nftgen.FirewallPlan {
	c.mu.Lock()
	defer c.mu.Unlock()
	facts.Tunnel = c.overlay.Tunnel
	return facts
}

func (c *modeComposer) DNS(fallback unboundgen.Plan) unboundgen.Plan {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.facts.DNS == nil {
		base := fallback
		base.OutgoingAddress = ""
		c.facts.DNS = &base
		c.persist()
	}
	out := *c.facts.DNS
	out.OutgoingAddress = c.overlay.DNSOut
	c.noteUnbound()
	return out
}

func (c *modeComposer) noteUnbound() {
	if c.overlay.Tunnel == nil || c.overlay.DNSOut != "" || c.onUnbound == nil {
		return
	}
	log.Printf("vpn: resolver applied without tunnel binding: the tunnel address is not known yet, it is restored on connect")
	go c.onUnbound()
}

func (c *modeComposer) DNSWith(facts unboundgen.Plan) unboundgen.Plan {
	c.mu.Lock()
	defer c.mu.Unlock()
	facts.OutgoingAddress = c.overlay.DNSOut
	c.noteUnbound()
	return facts
}

func (c *modeComposer) QoS(fallback qosgen.Plan) qosgen.Plan {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.facts.QoS == nil {
		base := fallback
		base.Tunnel = ""
		c.facts.QoS = &base
		c.persist()
	}
	return c.qosWithOverlay(*c.facts.QoS)
}

func (c *modeComposer) QoSWith(facts qosgen.Plan) qosgen.Plan {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.qosWithOverlay(facts)
}

func (c *modeComposer) qosWithOverlay(p qosgen.Plan) qosgen.Plan {
	p.Tunnel = ""
	if c.overlay.QoSTunnel != "" && ifaceExists(c.overlay.QoSTunnel) {
		p.Tunnel = c.overlay.QoSTunnel
	}
	return p
}
