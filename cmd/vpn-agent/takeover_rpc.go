package main

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/ratelimit"
	"github.com/vpn-vendor/vpn-panel-core/internal/takeover"
)

type takeoverConsent struct {
	IDs    []string `json:"ids"`
	Digest string   `json:"digest"`
}

type takeoverSelection struct {
	takeover.Plan
}

func (s takeoverSelection) Doomed() []string {
	var out []string
	for _, u := range planUnits(s.Plan) {
		out = append(out, unitShortName(u))
	}
	return out
}

func unitShortName(u string) string {
	if n := len(u) - len(".service"); n > 0 && u[n:] == ".service" {
		return u[:n]
	}
	return u
}

func (c *takeoverConsent) resolve(r *takeoverRunner, lans, planCards []string) (takeoverSelection, *agentrpc.ErrorObject) {
	if c == nil || len(c.IDs) == 0 {
		return takeoverSelection{}, nil
	}
	if r == nil {
		return takeoverSelection{}, takeoverChangedErr("захват машины в этой сборке недоступен")
	}
	plan, err := r.plan(lans, planCards)
	if err != nil {
		return takeoverSelection{}, internalErr("не удалось проверить, что мешает на сервере — попробуйте ещё раз", true)
	}
	if plan.Digest != c.Digest {
		return takeoverSelection{}, takeoverChangedErr("план изменился")
	}
	sel, err := plan.Select(c.IDs)
	if err != nil {
		return takeoverSelection{}, takeoverChangedErr(err.Error())
	}
	return takeoverSelection{Plan: sel}, nil
}

func takeoverChangedErr(detail string) *agentrpc.ErrorObject {
	return &agentrpc.ErrorObject{Code: codeNetTakeover,
		Message: "обстановка на сервере изменилась — проверьте список того, что панель выключит, ещё раз",
		Data:    map[string]any{"recoverable": false, "detail": detail}}
}

func takeoverNoWindowErr() *agentrpc.ErrorObject {
	return &agentrpc.ErrorObject{Code: codeNetTakeover,
		Message: "старое на сервере выключается только вместе с проверкой связи — примените настройки сети с окном подтверждения",
		Data:    map[string]any{"recoverable": false, "detail": "согласие на захват без окна подтверждения"}}
}

func takeoverBusyErr(err error) *agentrpc.ErrorObject {
	msg := "не удалось остановить старое на сервере — попробуйте ещё раз; если повторяется, обратитесь в поддержку"
	if errors.Is(err, errTakeoverBusy) {
		msg = "сервер ещё выключает старое после прошлого применения — подождите минуту и попробуйте ещё раз"
	}
	return &agentrpc.ErrorObject{Code: codeNetTakeBusy, Message: msg,
		Data: map[string]any{"recoverable": true, "detail": err.Error()}}
}

func takeoverPlanLimiter() *ratelimit.Limiter { return ratelimit.New(6, 1, 10*time.Second) }

func (r *takeoverRunner) takeoverPlanStatus(raw json.RawMessage) (any, *agentrpc.ErrorObject) {
	var p struct {
		LANs      []string `json:"lans"`
		PlanCards []string `json:"plan_cards"`

		StateOnly bool `json:"state_only"`
	}
	if len(raw) > 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &agentrpc.ErrorObject{Code: agentrpc.CodeInvalidParams,
				Message: "запрос к системной службе составлен неверно — обновите страницу; если повторяется, обратитесь в поддержку",
				Data:    map[string]any{"recoverable": false}}
		}
	}
	if p.StateOnly {
		return r.stateView(map[string]any{"items": []map[string]any{}}), nil
	}
	if !r.limiter.Allow("plan") {
		return nil, agentrpc.Busy(codeHostBusy, "проверка запрошена слишком часто — подождите", r.limiter.RetryIn("plan"))
	}
	cards, err := r.sys.cards()
	if err != nil {
		return nil, internalErr(errReadInterfaces, true)
	}
	known := map[string]bool{}
	for _, c := range cards {
		known[c.Name] = true
	}
	keep := func(in []string) []string {
		var out []string
		for _, n := range in {
			if known[n] {
				out = append(out, n)
			}
		}
		return out
	}
	plan, err := r.plan(keep(p.LANs), keep(p.PlanCards))
	if err != nil {
		return nil, internalErr("не удалось проверить, что мешает на сервере — попробуйте ещё раз", true)
	}
	items := make([]map[string]any, 0, len(plan.Items))
	for _, it := range plan.Items {
		items = append(items, map[string]any{
			"id": it.ID, "kind": it.Kind, "title": it.Title, "found": it.Found,
			"checked": it.Checked, "locked": it.Locked, "support": it.Support,
		})
	}
	return r.stateView(map[string]any{"digest": plan.Digest, "items": items}), nil
}

func (r *takeoverRunner) stateView(res map[string]any) map[string]any {
	st := r.status()
	res["state"] = st.State
	if st.State != "none" {
		res["failed"], res["residue"] = st.Failed, st.Residue
		if j, ok, err := r.readJournal(); ok && err == nil && j.Backup != "" {
			res["backup"] = j.Backup
		}
	}
	return res
}
