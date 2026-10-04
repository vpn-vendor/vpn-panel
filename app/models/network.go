package models

import "time"

type Interface struct {
	ID         uint      `gorm:"primaryKey"`
	Name       string    `gorm:"column:name"`
	MAC        string    `gorm:"column:mac"`
	Role       string    `gorm:"column:role"`
	IPv4Method string    `gorm:"column:ipv4_method"`
	IPv4CIDR   string    `gorm:"column:ipv4_cidr"`
	WANMetric  uint      `gorm:"column:wan_metric"`
	CreatedAt  time.Time `gorm:"column:created_at"`
	UpdatedAt  time.Time `gorm:"column:updated_at"`

	IPv4Gateway string `gorm:"column:ipv4_gateway"`
	IPv4DNS     string `gorm:"column:ipv4_dns"`

	PPPoEUsername string `gorm:"column:pppoe_username"`

	VLAN int `gorm:"column:vlan"`
}

func (Interface) TableName() string { return "interfaces" }

type DhcpReservation struct {
	ID        uint      `gorm:"primaryKey"`
	Label     string    `gorm:"column:label"`
	MAC       string    `gorm:"column:mac"`
	IP        string    `gorm:"column:ip"`
	Subnet    string    `gorm:"column:subnet"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

func (DhcpReservation) TableName() string { return "dhcp_reservations" }

type VPNProfile struct {
	ID           uint   `gorm:"primaryKey"`
	Name         string `gorm:"column:name"`
	Slug         string `gorm:"column:slug"`
	EndpointHost string `gorm:"column:endpoint_host"`
	EndpointPort int    `gorm:"column:endpoint_port"`
	PeerKey      string `gorm:"column:peer_key"`
	Addresses    string `gorm:"column:addresses"`
	AllowedIPs   string `gorm:"column:allowed_ips"`
	ConfigDNS    string `gorm:"column:config_dns"`
	ConfigMTU    int    `gorm:"column:config_mtu"`
	Keepalive    int    `gorm:"column:keepalive"`
	FullTunnel   bool   `gorm:"column:full_tunnel"`

	Protocol  string `gorm:"column:protocol"`
	Transport string `gorm:"column:transport"`

	VoiceFit  bool      `gorm:"column:voice_fit;default:true"`
	CreatedAt time.Time `gorm:"column:created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

func (VPNProfile) TableName() string { return "vpn_profiles" }

type VPNCheck struct {
	ID     uint   `gorm:"primaryKey"`
	Mode   string `gorm:"column:mode"`
	Report string `gorm:"column:report"`

	TunnelProfile string    `gorm:"column:tunnel_profile"`
	TunnelMode    string    `gorm:"column:tunnel_mode"`
	TunnelSession int64     `gorm:"column:tunnel_session"`
	CreatedAt     time.Time `gorm:"column:created_at"`
}

func (VPNCheck) TableName() string { return "vpn_checks" }
