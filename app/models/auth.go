package models

import "time"

type User struct {
	ID         uint       `gorm:"primaryKey"`
	Name       string     `gorm:"column:name"`
	IsActive   bool       `gorm:"column:is_active"`
	LastSeenAt *time.Time `gorm:"column:last_seen_at"`
	CreatedAt  time.Time  `gorm:"column:created_at"`
	UpdatedAt  time.Time  `gorm:"column:updated_at"`
}

func (User) TableName() string { return "users" }

type TrustedDevice struct {
	ID                uint       `gorm:"primaryKey"`
	UserID            uint       `gorm:"column:user_id"`
	TokenHash         string     `gorm:"column:token_hash"`
	Label             string     `gorm:"column:label"`
	UserAgent         string     `gorm:"column:user_agent"`
	LastIP            string     `gorm:"column:last_ip"`
	EnrolledVia       string     `gorm:"column:enrolled_via"`
	LastUsedAt        time.Time  `gorm:"column:last_used_at"`
	AbsoluteExpiresAt time.Time  `gorm:"column:absolute_expires_at"`
	QuarantineUntil   *time.Time `gorm:"column:quarantine_until"`
	RevokedAt         *time.Time `gorm:"column:revoked_at"`
	RevokedBy         *string    `gorm:"column:revoked_by"`
	CreatedAt         time.Time  `gorm:"column:created_at"`
}

func (TrustedDevice) TableName() string { return "trusted_devices" }

type EnrollCode struct {
	ID               uint       `gorm:"primaryKey"`
	CodeHash         string     `gorm:"column:code_hash"`
	UserID           uint       `gorm:"column:user_id"`
	IssuedVia        string     `gorm:"column:issued_via"`
	IssuedByDeviceID *uint      `gorm:"column:issued_by_device_id"`
	ExpiresAt        time.Time  `gorm:"column:expires_at"`
	UsedAt           *time.Time `gorm:"column:used_at"`
	UsedByIP         *string    `gorm:"column:used_by_ip"`
	CreatedAt        time.Time  `gorm:"column:created_at"`
}

func (EnrollCode) TableName() string { return "enroll_codes" }

type AuthEvent struct {
	ID         uint      `gorm:"primaryKey"`
	Event      string    `gorm:"column:event"`
	UserID     *uint     `gorm:"column:user_id"`
	DeviceID   *uint     `gorm:"column:device_id"`
	IP         string    `gorm:"column:ip"`
	Details    string    `gorm:"column:details"`
	OccurredAt time.Time `gorm:"column:occurred_at"`

	RepeatCount int        `gorm:"column:repeat_count"`
	LastAt      *time.Time `gorm:"column:last_at"`
}

func (AuthEvent) TableName() string { return "auth_events" }

type Setting struct {
	Key       string    `gorm:"primaryKey;column:key"`
	Value     string    `gorm:"column:value"`
	UpdatedAt time.Time `gorm:"column:updated_at"`
}

func (Setting) TableName() string { return "settings" }
