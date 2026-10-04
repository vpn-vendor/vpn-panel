package cgroupstat

import "testing"

func TestPressureSomeAvg10(t *testing.T) {
	raw := []byte("some avg10=3.37 avg60=1.17 avg300=0.27 total=859047\nfull avg10=3.29 avg60=1.14 avg300=0.26 total=826987\n")
	v, ok := pressureSomeAvg10(raw)
	if !ok || v != 3.37 {
		t.Fatalf("avg10: %v %v", v, ok)
	}
	for name, bad := range map[string][]byte{
		"пусто":            nil,
		"только full":      []byte("full avg10=1.0 avg60=0 avg300=0 total=0\n"),
		"без avg10":        []byte("some avg60=1.0 total=0\n"),
		"мусор в значении": []byte("some avg10=abc avg60=0\n"),
		"вне диапазона":    []byte("some avg10=250 avg60=0\n"),
	} {
		if _, ok := pressureSomeAvg10(bad); ok {
			t.Errorf("%s: принято", name)
		}
	}
}
