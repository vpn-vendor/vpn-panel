package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/vpn-vendor/vpn-panel-core/internal/durable"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const CommonName = "gateway"

const legacyCommonName = "vpn-panel"

const Validity = 10 * 365 * 24 * time.Hour

const Backdate = 30 * 24 * time.Hour

func EnsureCertificate(certPath, keyPath string, extraHosts []string) error {
	if pairIsUsable(certPath, keyPath, extraHosts) {
		return nil
	}
	return generate(certPath, keyPath, extraHosts)
}

func pairIsUsable(certPath, keyPath string, extraHosts []string) bool {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}
	if !time.Now().Before(leaf.NotAfter) {
		return false
	}

	if leaf.Subject.CommonName == legacyCommonName {
		return false
	}
	have := map[string]bool{}
	for _, n := range leaf.DNSNames {
		have[n] = true
	}
	for _, h := range extraHosts {
		if h != "" && net.ParseIP(h) == nil && !have[h] {
			return false
		}
	}
	return true
}

func generate(certPath, keyPath string, extraHosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: CommonName},
		NotBefore:             time.Now().Add(-Backdate),
		NotAfter:              time.Now().Add(Validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := append([]string{"vpn.lan", "localhost"}, extraHosts...)
	if hostname, herr := os.Hostname(); herr == nil && hostname != "" {
		hosts = append(hosts, hostname)
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	template.IPAddresses = append(template.IPAddresses, net.ParseIP("127.0.0.1"))

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	if err := durable.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
		return err
	}
	if err := durable.MkdirAll(filepath.Dir(keyPath), 0o750); err != nil {
		return err
	}

	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := durable.Write(keyPath, keyOut, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if err := durable.Write(certPath, certOut, 0o644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	if !pairIsUsable(certPath, keyPath, extraHosts) {
		return errors.New("generated certificate failed self-check")
	}
	return nil
}
