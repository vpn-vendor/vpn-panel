package models

import "time"

type Boot struct {
	ID uint `gorm:"primaryKey"`

	BootID       string    `gorm:"column:boot_id"`
	BootedAt     time.Time `gorm:"column:booted_at"`
	FirstStartAt time.Time `gorm:"column:first_start_at"`
	LastStartAt  time.Time `gorm:"column:last_start_at"`
	PanelStarts  int       `gorm:"column:panel_starts"`

	SeenAt time.Time `gorm:"column:seen_at"`

	CleanStop bool `gorm:"column:clean_stop"`
}

func (Boot) TableName() string { return "boots" }
