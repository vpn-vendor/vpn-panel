package oswindow

import (
	"testing"
	"time"
)

func TestWindow(t *testing.T) {
	got := Supported()
	if len(got) != 2 || got[0] != (Release{"22.04", "jammy"}) || got[1] != (Release{"26.04", "resolute"}) {
		t.Fatalf("окно %+v", got)
	}
	if _, ok := Find("noble"); ok {
		t.Fatal("24.04 в окно не входит")
	}
	if r, ok := Find("jammy"); !ok || r.Version != "22.04" {
		t.Fatalf("jammy: %+v %v", r, ok)
	}
}

const distroInfo = `version,codename,series,created,release,eol,eol-server,eol-esm,eol-legacy
22.04 LTS,Jammy Jellyfish,jammy,2021-10-14,2022-04-21,2027-06-01,2027-06-01,2032-04-21,2037-04-30
26.04 LTS,Resolute Raccoon,resolute,2025-10-09,2026-04-23,2031-05-29,2031-05-29,2036-04-23,2041-04-30
`

func TestEOLFromUbuntuData(t *testing.T) {
	for codename, want := range map[string]string{"jammy": "2027-06-01", "resolute": "2031-05-29"} {
		got, ok := EOL([]byte(distroInfo), codename)
		if !ok || got.Format(time.DateOnly) != want {
			t.Errorf("%s: %v %v, ждали %s", codename, got, ok, want)
		}
	}
	if _, ok := EOL([]byte(distroInfo), "noble"); ok {
		t.Error("выпуска нет в данных — срока нет")
	}
}

func TestEOLSurvivesNewColumns(t *testing.T) {
	data := "series,extra,eol\njammy,x,2027-06-01\n"
	if got, ok := EOL([]byte(data), "jammy"); !ok || got.Format(time.DateOnly) != "2027-06-01" {
		t.Fatalf("%v %v", got, ok)
	}
	if _, ok := EOL([]byte("version,codename\n22.04,Jammy\n"), "jammy"); ok {
		t.Fatal("без нужных столбцов срока нет")
	}
	if _, ok := EOL([]byte("series,eol\njammy,не дата\n"), "jammy"); ok {
		t.Fatal("нечитаемая дата — срока нет")
	}
}

func TestEOLWithShortOldRows(t *testing.T) {
	data := "version,codename,series,created,release,eol,eol-server,eol-esm,eol-legacy\n" +
		"4.10,Warty Warthog,warty,2004-03-05,2004-10-20,2006-04-30\n" +
		"22.04 LTS,Jammy Jellyfish,jammy,2021-10-14,2022-04-21,2027-06-01,2027-06-01,2032-04-21,2037-04-30\n"
	if got, ok := EOL([]byte(data), "jammy"); !ok || got.Format(time.DateOnly) != "2027-06-01" {
		t.Fatalf("%v %v", got, ok)
	}
}
