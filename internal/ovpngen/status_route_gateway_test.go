package ovpngen

import "testing"

func TestPushedRouteGateway(t *testing.T) {
	line := "2026-09-07 17:59:19 us=98860 PUSH: Received control message: " +
		"'PUSH_REPLY,redirect-gateway def1,dhcp-option DNS 10.77.77.1," +
		"route 192.168.100.0 255.255.255.0,route-gateway 10.77.77.1,topology subnet," +
		"ifconfig 10.77.77.2 255.255.255.0,peer-id 1,cipher AES-256-GCM'"
	if got := PushedRouteGateway(ParsePushReply(line)); got != "10.77.77.1" {
		t.Fatalf("адрес дальнего конца: получили %q, ждали 10.77.77.1", got)
	}

	if got := PushedRouteGateway([]string{"redirect-gateway def1", "topology subnet"}); got != "" {
		t.Fatalf("без route-gateway ждали пусто, получили %q", got)
	}

	for _, bad := range []string{"route-gateway ", "route-gateway not-an-ip",
		"route-gateway 10.77.77.1; rm -rf /", "route-gateway ::1"} {
		if got := PushedRouteGateway([]string{bad}); got != "" {
			t.Fatalf("на %q ждали пусто, получили %q", bad, got)
		}
	}
}
