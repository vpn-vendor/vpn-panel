package bootstrap

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/goravel/framework/contracts/foundation"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/app/http/controllers"
	"github.com/vpn-vendor/vpn-panel-core/app/services/diag"
	"github.com/vpn-vendor/vpn-panel-core/app/services/listen"
	"github.com/vpn-vendor/vpn-panel-core/app/services/metrics"
	"github.com/vpn-vendor/vpn-panel-core/app/services/network"
	"github.com/vpn-vendor/vpn-panel-core/app/services/overload"
	"github.com/vpn-vendor/vpn-panel-core/app/services/pathmon"
	"github.com/vpn-vendor/vpn-panel-core/app/services/reliability"
	"github.com/vpn-vendor/vpn-panel-core/app/services/restore"
	"github.com/vpn-vendor/vpn-panel-core/app/services/retention"
	"github.com/vpn-vendor/vpn-panel-core/app/services/security"
	"github.com/vpn-vendor/vpn-panel-core/app/services/securitylog"
	"github.com/vpn-vendor/vpn-panel-core/app/services/settings"
	"github.com/vpn-vendor/vpn-panel-core/app/services/vpn"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
	"github.com/vpn-vendor/vpn-panel-core/internal/devmode"
	"github.com/vpn-vendor/vpn-panel-core/internal/httpredirect"
	"github.com/vpn-vendor/vpn-panel-core/internal/httpserve"
	"github.com/vpn-vendor/vpn-panel-core/internal/multilisten"
	"github.com/vpn-vendor/vpn-panel-core/internal/netplangen"
	"github.com/vpn-vendor/vpn-panel-core/internal/tlscert"
	"github.com/vpn-vendor/vpn-panel-core/internal/unboundgen"
	"github.com/vpn-vendor/vpn-panel-core/internal/vpnproto"
)

var (
	httpsListener    *multilisten.Listener
	redirectListener *multilisten.Listener
	externalTLSPort  string
)

func PrepareWeb() error {
	config := facades.Config()

	certPath := config.GetString("http.tls.ssl.cert")
	keyPath := config.GetString("http.tls.ssl.key")

	var hosts []string
	for _, short := range unboundgen.ShortNames {
		hosts = append(hosts, short, short+"."+unboundgen.LocalDomain)
	}
	if err := tlscert.EnsureCertificate(certPath, keyPath, hosts); err != nil {
		return fmt.Errorf("tls certificate: %w", err)
	}

	tlsPort, err := strconv.Atoi(config.GetString("http.tls.port"))
	if err != nil || tlsPort <= 0 || tlsPort > 65535 {
		return fmt.Errorf("tls port: invalid value %q", config.GetString("http.tls.port"))
	}
	httpsListener = multilisten.New(tlsPort, log.Printf)

	httpsListener.SetPerAddressLimit(httpserve.PerAddressConns)

	if redirectPort := config.GetString("http.redirect_port"); redirectPort != "" {
		port, err := strconv.Atoi(redirectPort)
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("redirect port: invalid value %q", redirectPort)
		}
		redirectListener = multilisten.New(port, log.Printf)
		redirectListener.SetPerAddressLimit(httpserve.PerAddressConns)
	}

	externalTLSPort = config.GetString("http.external_tls_port")
	if externalTLSPort == "" {
		externalTLSPort = config.GetString("http.tls.port")
	}

	if devmode.Enabled {
		log.Printf("vpn-panel: режим разработки (тег сборки dev) — панель слушает все адреса")
	}

	listen.Init(httpsListener, redirectListener, devmode.Enabled, network.New().AppliedLANs, log.Printf)
	return nil
}

func Runners() []foundation.Runner {

	retention.OnSweep(diag.ExpireFullCheck)
	controllers.PathMonitor = pathMonitor
	controllers.MetricsRoles = metricsRoles
	return []foundation.Runner{
		httpserve.NewRunner("vpn-panel:https", nil, startHTTPS),
		httpserve.NewRunner("vpn-panel:redirect", func() bool {
			return facades.Config().GetString("http.redirect_port") != ""
		}, startRedirect),

		retention.NewRunner(),

		reliability.NewRunner(),

		metrics.NewRunner(retention.DataDir(), metricsRoles, pathMonitor().Source()),
		pathmon.NewRunner(pathMonitor()),

		security.NewLeakRunner(),

		restore.NewRunner(),

		network.NewRunner(),
	}
}

func requestTimeout() time.Duration {
	return time.Duration(facades.Config().GetInt("http.request_timeout", 120)) * time.Second
}

func startHTTPS() (*http.Server, func(*http.Server) error, error) {
	if httpsListener == nil {
		return nil, nil, fmt.Errorf("listener is not prepared")
	}
	config := facades.Config()

	headerLimit := config.GetInt(fmt.Sprintf("http.drivers.%s.header_limit", config.GetString("http.default")), 4096) << 10

	srv := httpserve.New(overload.Wrap(httpserve.Multipart(http.AllowQuerySemicolons(facades.Route()), backupfile.MaxBytes)),
		requestTimeout(), headerLimit)
	cert, key := config.GetString("http.tls.ssl.cert"), config.GetString("http.tls.ssl.key")
	return srv, func(s *http.Server) error { return s.ServeTLS(httpsListener, cert, key) }, nil
}

func startRedirect() (*http.Server, func(*http.Server) error, error) {
	if redirectListener == nil {
		return nil, nil, fmt.Errorf("redirect listener is not prepared")
	}
	srv := httpserve.New(httpredirect.Handler(externalTLSPort), requestTimeout(), 1<<20)
	return srv, func(s *http.Server) error { return s.Serve(redirectListener) }, nil
}

func metricsRoles() metrics.Roles {
	var r metrics.Roles
	net := network.New()
	for _, role := range net.Roles() {
		switch role.Role {
		case netplangen.RoleWAN:
			r.WAN = netplangen.EffectiveWAN(netplangen.LinkIface(role.Name, role.VLAN), role.IPv4Method)
		case netplangen.RoleLAN:
			r.LANs = append(r.LANs, role.Name)
		}
	}
	v := vpn.New()
	if st := v.Load(); st.Mode == vpn.ModeBlack && st.ActiveSlug != "" {
		if p, ok := v.Profile(st.ActiveSlug); ok {
			r.Tunnel = vpnproto.Iface(vpnproto.Stored(p.Protocol))
		}
	}
	return r
}

var (
	pathOnce sync.Once
	pathSvc  *pathmon.Service
)

func pathMonitor() *pathmon.Service {
	pathOnce.Do(func() {
		v := vpn.New()
		pathSvc = pathmon.New(pathmon.Deps{
			Roles: func() pathmon.Roles {
				mr := metricsRoles()
				st := v.Load()
				r := pathmon.Roles{Mode: st.Mode, Slug: st.ActiveSlug, Tunnel: mr.Tunnel, WAN: mr.WAN}
				if p, ok := v.Profile(st.ActiveSlug); ok {
					r.Protocol, r.Addresses = p.Protocol, p.Addresses
					pp, _ := vpnproto.Passport(vpnproto.Stored(p.Protocol), p.Transport)
					r.Candidates = pp.ProbeCandidates
				}
				return r
			},
			PeerIPv4: func() string {
				if st, err := v.Status(); err == nil {
					return st.PeerIPv4
				}
				return ""
			},
			AdminTarget: v.ProbeTarget,
			Upstream:    func() []string { return unboundgen.Upstream },
			Collecting: func() bool {
				col := metrics.Current()
				return col != nil && col.Effective(pathmon.SourceName).Collects()
			},
			Record: securitylog.Record,
			Get:    settings.Get,
			Set:    settings.Set,
		})
	})
	return pathSvc
}
