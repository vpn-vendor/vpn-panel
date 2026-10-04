package network

import (
	"encoding/json"
	"errors"
	"log"
	"sync"

	"github.com/vpn-vendor/vpn-panel-core/app/services/security"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
)

const SettingPendingApply = "network.pending_apply"

var ErrAwaiting = errors.New("предыдущее изменение сети ещё ждёт подтверждения — подтвердите или откатите его")

type pendingApply struct {
	Network  Section          `json:"network"`
	Security security.Section `json:"security"`

	Before string `json:"before"`
	After  string `json:"after,omitempty"`
}

type planState struct {
	Awaiting bool   `json:"awaiting"`
	Hash     string `json:"hash"`
}

func (s *Service) planState() (planState, error) {
	var st planState
	resp, err := s.client().Call("network.pending", map[string]any{})
	if err != nil {
		return st, err
	}
	if resp.Error != nil {
		return st, resp.Error
	}
	return st, json.Unmarshal(resp.Result, &st)
}

func loadPending() (*pendingApply, bool) {
	raw := settings.Get(SettingPendingApply)
	if raw == "" {
		return nil, false
	}
	var p pendingApply
	if err := json.Unmarshal([]byte(raw), &p); err != nil {

		log.Printf("network: отметка ожидающего изменения не читается и снята: %v", err)
		_ = settings.Set(SettingPendingApply, "")
		return nil, false
	}
	return &p, true
}

func storePending(p *pendingApply) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	if err := settings.Set(SettingPendingApply, string(raw)); err != nil {
		return err
	}
	return settings.Durable()
}

func (s *Service) BeginChange() error {
	if _, err := s.settle(true); err != nil {
		return err
	}
	if _, ok := loadPending(); ok {
		return ErrAwaiting
	}
	st, err := s.planState()
	if err != nil {
		return err
	}
	if st.Awaiting {
		return ErrAwaiting
	}
	net, err := ReadSection()
	if err != nil {
		return err
	}
	sec, err := security.ReadSection()
	if err != nil {
		return err
	}
	return storePending(&pendingApply{Network: net, Security: sec, Before: st.Hash})
}

func (s *Service) noteApplied() {
	p, ok := loadPending()
	if !ok {
		return
	}
	st, err := s.planState()
	if err != nil {
		return
	}
	p.After = st.Hash
	if err := storePending(p); err != nil {
		log.Printf("network: отметка ожидающего изменения не обновлена: %v", err)
	}
}

func (s *Service) CommitChange() {
	if _, ok := loadPending(); !ok {
		return
	}
	if err := settings.Set(SettingPendingApply, ""); err != nil {
		log.Printf("network: отметка ожидающего изменения не снята: %v", err)
		return
	}
	if err := settings.Durable(); err != nil {
		log.Printf("network: %v", err)
	}
}

func (s *Service) RevertChange() (bool, error) {
	p, ok := loadPending()
	if !ok {
		return false, nil
	}
	cur, err := ReadSection()
	if err != nil {
		return false, err
	}
	if err := ApplySection(cur, p.Network); err != nil {
		return false, err
	}
	sec, err := security.ReadSection()
	if err != nil {
		return false, err
	}
	if err := security.ApplySection(sec, p.Security); err != nil {
		return false, err
	}
	if err := settings.Set(SettingPendingApply, ""); err != nil {
		return false, err
	}
	return true, settings.Durable()
}

func (s *Service) Reconcile() (bool, error) {
	if !changeMu.TryLock() {
		return false, nil
	}
	defer changeMu.Unlock()
	return s.settle(true)
}

var changeMu sync.Mutex

func (s *Service) settle(unattended bool) (bool, error) {
	p, ok := loadPending()
	if !ok {
		return false, nil
	}
	st, err := s.planState()
	if err != nil {
		return false, err
	}
	if st.Awaiting {
		return false, nil
	}
	settled := st.Hash != p.Before
	if p.After != "" {
		settled = st.Hash == p.After
	}
	if settled {

		s.markApplied(s.BuildPlan())
		s.CommitChange()
		return false, nil
	}
	reverted, err := s.RevertChange()
	if err != nil {
		return false, err
	}
	if reverted {
		s.clearPending()
	}
	if reverted && unattended {
		s.Audit("network_unconfirmed", "", "окно подтверждения закрылось без человека — настройки панели возвращены к действующим")
	}
	return reverted, nil
}
