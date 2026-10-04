package controllers

import (
	"math"
	"strconv"
	"strings"
	"time"

	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	imetrics "github.com/vpn-vendor/vpn-panel-core/internal/metrics"
)

type MetricsController struct{}

func NewMetricsController() *MetricsController { return &MetricsController{} }

const maxRowsPerQuery = 32

func (c *MetricsController) Series(ctx contractshttp.Context) contractshttp.Response {
	col := metrics.Current()
	if col == nil {
		return ctx.Response().Status(503).Json(contractshttp.Json{"error": "сбор показателей ещё не запущен"})
	}
	rows := strings.Split(ctx.Request().Query("rows"), ",")
	if len(rows) > maxRowsPerQuery {
		rows = rows[:maxRowsPerQuery]
	}
	now := time.Now()
	to := unixParam(ctx.Request().Query("to"), now)
	from := unixParam(ctx.Request().Query("from"), to.Add(-time.Hour))
	if !from.Before(to) {
		from = to.Add(-time.Hour)
	}
	width, _ := strconv.Atoi(ctx.Request().Query("width"))
	res := col.Query(rows, from, to, width)
	out := map[string][][]any{}
	for name, pts := range res.Rows {
		arr := make([][]any, len(pts))
		for i, p := range pts {
			arr[i] = []any{jsonNum(p.Min), jsonNum(p.Avg), jsonNum(p.Max)}
		}
		out[name] = arr
	}
	return ctx.Response().Success().Json(contractshttp.Json{
		"from":   res.From.Unix() - res.From.Unix()%int64(res.Plan.Step/time.Second),
		"step":   int64(res.Plan.Step / time.Second),
		"tier":   res.Plan.Tier,
		"master": col.Master().Mode.String(),
		"rows":   out,
	})
}

func unixParam(s string, def time.Time) time.Time {
	u, err := strconv.ParseInt(s, 10, 64)
	if err != nil || u <= 0 {
		return def
	}
	return time.Unix(u, 0)
}

func jsonNum(v float64) any {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return nil
	}
	return math.Round(v*100) / 100
}

var _ = imetrics.MaxPoints
