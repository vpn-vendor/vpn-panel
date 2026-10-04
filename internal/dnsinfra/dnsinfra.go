package dnsinfra

import (
	"bufio"
	"bytes"
	"net"
	"strconv"
	"strings"
)

type Server struct {
	IP     string  `json:"ip"`
	Zone   string  `json:"zone"`
	PingMs float64 `json:"ping_ms"`
	VarMs  float64 `json:"var_ms"`
	TTL    int     `json:"ttl"`
}

func Parse(out []byte, only []string) []Server {
	allowed := map[string]bool{}
	for _, ip := range only {
		allowed[ip] = true
	}
	var res []Server
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || net.ParseIP(f[0]) == nil {
			continue
		}
		if len(allowed) > 0 && !allowed[f[0]] {
			continue
		}
		s := Server{IP: f[0], Zone: f[1]}
		for i := 2; i+1 < len(f); i += 2 {
			v, err := strconv.ParseFloat(f[i+1], 64)
			if err != nil {
				continue
			}
			switch f[i] {
			case "ttl":
				s.TTL = int(v)
			case "ping":
				s.PingMs = v
			case "var":
				s.VarMs = v
			}
		}
		res = append(res, s)
	}
	return res
}
