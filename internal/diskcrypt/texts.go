package diskcrypt

import (
	_ "embed"
	"strings"
)

//go:embed texts.tsv
var textsTSV string

func Text(code string) string {
	for _, line := range strings.Split(textsTSV, "\n") {
		if k, v, ok := strings.Cut(line, "\t"); ok && k == code {
			return v
		}
	}
	return code
}
