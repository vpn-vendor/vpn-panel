package system

import "encoding/json"

type TakeoverItem struct {
	ID      string   `json:"id"`
	Kind    string   `json:"kind"`
	Title   string   `json:"title"`
	Found   string   `json:"found"`
	Checked bool     `json:"checked"`
	Locked  bool     `json:"locked"`
	Support []string `json:"support"`
}

type TakeoverPlan struct {
	Digest string         `json:"digest"`
	State  string         `json:"state"`
	Items  []TakeoverItem `json:"items"`
	Failed int            `json:"failed"`

	Residue []string `json:"residue"`
	Backup  string   `json:"backup"`
}

func (p TakeoverPlan) Selectable() int {
	n := 0
	for _, it := range p.Items {
		if !it.Locked {
			n++
		}
	}
	return n
}

func (s *Service) TakeoverPlan(lans, cards []string) (TakeoverPlan, error) {
	return s.takeover(map[string]any{"lans": lans, "plan_cards": cards})
}

func (s *Service) TakeoverState() (TakeoverPlan, error) {
	return s.takeover(map[string]any{"state_only": true})
}

func (s *Service) takeover(params map[string]any) (TakeoverPlan, error) {
	var p TakeoverPlan
	resp, err := s.client().Call("host.takeover_plan", params)
	if err != nil {
		return p, err
	}
	if resp.Error != nil {
		return p, resp.Error
	}
	err = json.Unmarshal(resp.Result, &p)
	return p, err
}
