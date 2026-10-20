package oswindow

import (
	"bytes"
	_ "embed"
	"encoding/csv"
	"strings"
	"time"
)

//go:embed window.txt
var windowText string

const DistroInfoPath = "/usr/share/distro-info/ubuntu.csv"

type Release struct {
	Version  string
	Codename string
}

func Supported() []Release {
	var out []Release
	for _, line := range strings.Split(windowText, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		out = append(out, Release{Version: f[0], Codename: f[1]})
	}
	return out
}

func Find(codename string) (Release, bool) {
	for _, r := range Supported() {
		if r.Codename == codename {
			return r, true
		}
	}
	return Release{}, false
}

func EOL(distroInfo []byte, codename string) (time.Time, bool) {
	r := csv.NewReader(bytes.NewReader(distroInfo))

	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil || len(rows) < 2 {
		return time.Time{}, false
	}
	series, eol := -1, -1
	for i, name := range rows[0] {
		switch name {
		case "series":
			series = i
		case "eol":
			eol = i
		}
	}
	if series < 0 || eol < 0 {
		return time.Time{}, false
	}
	for _, row := range rows[1:] {
		if len(row) > series && len(row) > eol && row[series] == codename {
			t, err := time.Parse("2006-01-02", row[eol])
			return t, err == nil
		}
	}
	return time.Time{}, false
}
