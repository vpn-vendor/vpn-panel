package controllers

import (
	contractshttp "github.com/goravel/framework/contracts/http"

	"github.com/vpn-vendor/vpn-panel-core/app/http/navigation"
	"github.com/vpn-vendor/vpn-panel-core/app/http/ui"
)

type SearchController struct{}

func NewSearchController() *SearchController { return &SearchController{} }

type searchResult struct {
	Title, Hint, URL, Section string
}

func (c *SearchController) Index(ctx contractshttp.Context) contractshttp.Response {

	query := ctx.Request().Query("q")
	found := navigation.Search(query)
	results := make([]searchResult, 0, len(found))
	for _, e := range found {
		section := ""
		if s, ok := navigation.SectionByKey(e.Section); ok {
			section = s.Title
		}
		results = append(results, searchResult{Title: e.Title, Hint: e.Hint, URL: e.URL, Section: section})
	}

	if ctx.Request().Query("format") == "json" {
		items := make([]contractshttp.Json, 0, len(results))
		for _, r := range results {
			items = append(items, contractshttp.Json{"title": r.Title, "hint": r.Hint, "url": r.URL, "section": r.Section})
		}
		return ctx.Response().Success().Json(contractshttp.Json{"items": items})
	}

	view := map[string]any{
		"query":       query,
		"searchQuery": query,
		"results":     results,
		"searchField": ui.Field{
			ID: "search-page-q", Name: "q", Type: "search", Label: "Что найти", Value: query,
			Placeholder: "Например: PPPoE, скорость, код входа", MaxLength: navigation.MaxQueryRunes,
			Autocomplete: "off",
		},
		"searchButton": ui.Button{Label: "Найти"},
	}
	return ctx.Response().View().Make("search.tmpl", page(ctx, "Поиск", "search", view))
}
