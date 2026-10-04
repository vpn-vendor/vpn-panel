package models

import "time"

type Device struct {
	ID          uint   `gorm:"primaryKey"`
	MAC         string `gorm:"column:mac"`
	Hostname    string `gorm:"column:hostname"`
	LastIP      string `gorm:"column:last_ip"`
	Label       string `gorm:"column:label"`
	Location    string `gorm:"column:location"`
	Owner       string `gorm:"column:owner"`
	Note        string `gorm:"column:note"`
	LabelSource string `gorm:"column:label_source"`

	PublicLabel     string     `gorm:"column:public_label"`
	LabelReviewedAt *time.Time `gorm:"column:label_reviewed_at"`

	IdentifyRequestedAt *time.Time `gorm:"column:identify_requested_at"`
	IdentifyNote        string     `gorm:"column:identify_note"`
	IdentifyIP          string     `gorm:"column:identify_ip"`
	IdentifySegment     string     `gorm:"column:identify_segment"`
	IdentifyCount       int        `gorm:"column:identify_count"`
	ProposedLabel       string     `gorm:"column:proposed_label"`
	ProposedLocation    string     `gorm:"column:proposed_location"`
	ProposedOwner       string     `gorm:"column:proposed_owner"`
	ProposedIP          string     `gorm:"column:proposed_ip"`
	ProposedAt          *time.Time `gorm:"column:proposed_at"`
	LanMbit             int        `gorm:"column:lan_mbit"`
	LanIdleMs           float64    `gorm:"column:lan_idle_ms"`
	LanLoadMs           float64    `gorm:"column:lan_load_ms"`
	LanTestedAt         *time.Time `gorm:"column:lan_tested_at"`
	FirstSeenAt         time.Time  `gorm:"column:first_seen_at"`
	LastSeenAt          time.Time  `gorm:"column:last_seen_at"`
	CreatedAt           time.Time  `gorm:"column:created_at"`
	UpdatedAt           time.Time  `gorm:"column:updated_at"`
}

func (Device) TableName() string { return "devices" }
