package netstatus

import "testing"

func TestPermanentAddressStaysIdentity(t *testing.T) {
	addr := []byte(`[{"ifname":"ens2","operstate":"UP","address":"00:1a:2b:3c:4d:5e","permaddr":"52:54:00:00:00:02","link_type":"ether","addr_info":[]},
	{"ifname":"ens3","operstate":"UP","address":"52:54:00:00:00:03","link_type":"ether","addr_info":[]}]`)
	st, err := Parse(addr, []byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	if st.Interfaces[0].MAC != "52:54:00:00:00:02" || st.Interfaces[0].Presented != "00:1a:2b:3c:4d:5e" {
		t.Errorf("подменённая карта: %+v", st.Interfaces[0])
	}
	if st.Interfaces[1].MAC != "52:54:00:00:00:03" || st.Interfaces[1].Presented != "" {
		t.Errorf("обычная карта: %+v", st.Interfaces[1])
	}
}

func TestParseNeighbors(t *testing.T) {
	list, err := ParseNeighbors([]byte(`[{"dst":"10.0.0.1","dev":"ens2","lladdr":"00:1A:2B:3C:4D:5E","state":["REACHABLE"]},
	{"dst":"10.0.0.9","dev":"ens2","state":["FAILED"]}]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].MAC != "00:1a:2b:3c:4d:5e" || list[0].Dev != "ens2" {
		t.Errorf("соседи: %+v", list)
	}
}
