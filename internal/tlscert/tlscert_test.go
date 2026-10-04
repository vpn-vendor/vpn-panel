package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func paths(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "tls", "cert.pem"), filepath.Join(dir, "tls", "key.pem")
}

func TestGeneratesUsablePair(t *testing.T) {
	certPath, keyPath := paths(t)
	if err := EnsureCertificate(certPath, keyPath, []string{"10.0.0.1", "office.lan"}); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("load pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := leaf.VerifyHostname("vpn.lan"); err != nil {
		t.Fatalf("vpn.lan not in SAN: %v", err)
	}
	if err := leaf.VerifyHostname("office.lan"); err != nil {
		t.Fatalf("extra host not in SAN: %v", err)
	}
	if err := leaf.VerifyHostname("10.0.0.1"); err != nil {
		t.Fatalf("extra IP not in SAN: %v", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("loopback not in SAN: %v", err)
	}

	if !leaf.NotBefore.Before(time.Now().Add(-7 * 24 * time.Hour)) {
		t.Fatalf("NotBefore must be backdated by weeks, got %v", leaf.NotBefore)
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key permissions: want 0600, got %o", info.Mode().Perm())
	}
}

func TestIdempotentOnValidPair(t *testing.T) {
	certPath, keyPath := paths(t)
	if err := EnsureCertificate(certPath, keyPath, nil); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	before, _ := os.ReadFile(certPath) //nolint:gosec
	if err := EnsureCertificate(certPath, keyPath, nil); err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	after, _ := os.ReadFile(certPath) //nolint:gosec
	if string(before) != string(after) {
		t.Fatal("valid pair was regenerated")
	}
}

func TestRegeneratesBrokenPair(t *testing.T) {
	certPath, keyPath := paths(t)
	if err := os.MkdirAll(filepath.Dir(certPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte("garbage"), 0o644); err != nil { //nolint:gosec

		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureCertificate(certPath, keyPath, nil); err != nil {
		t.Fatalf("ensure over garbage: %v", err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("pair not usable after regeneration: %v", err)
	}
}

func TestRegeneratesWhenNameMissing(t *testing.T) {
	certPath, keyPath := paths(t)
	if err := EnsureCertificate(certPath, keyPath, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(certPath) //nolint:gosec
	if err := EnsureCertificate(certPath, keyPath, []string{"pc", "pc.vpn.lan"}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(certPath) //nolint:gosec
	if string(before) == string(after) {
		t.Fatal("сертификат без имени pc обязан пересоздаться")
	}
	pair, _ := tls.LoadX509KeyPair(certPath, keyPath)
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	if err := leaf.VerifyHostname("pc.vpn.lan"); err != nil {
		t.Fatalf("pc.vpn.lan not in SAN: %v", err)
	}
	if err := EnsureCertificate(certPath, keyPath, []string{"pc"}); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(certPath); string(again) != string(after) { //nolint:gosec
		t.Fatal("с уже присутствующим именем пара не трогается")
	}
}

func TestCommonNameIsNeutral(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := EnsureCertificate(cert, key, nil); err != nil {
		t.Fatalf("генерация: %v", err)
	}
	leaf := readLeaf(t, cert)
	if leaf.Subject.CommonName != CommonName {
		t.Fatalf("имя в сертификате %q, ждали %q", leaf.Subject.CommonName, CommonName)
	}
	if strings.Contains(strings.ToLower(leaf.Subject.String()), "vpn-panel") {
		t.Fatalf("в подписи сертификата название продукта: %s", leaf.Subject.String())
	}
}

func TestRegeneratesLegacyIdentifyingName(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writeLegacyPair(t, cert, key)
	if got := readLeaf(t, cert).Subject.CommonName; got != legacyCommonName {
		t.Fatalf("подготовка: ждали прежнее имя, получили %q", got)
	}

	if err := EnsureCertificate(cert, key, nil); err != nil {
		t.Fatalf("перевыпуск: %v", err)
	}
	after := readLeaf(t, cert)
	if after.Subject.CommonName != CommonName {
		t.Fatalf("прежняя пара не перевыпущена: имя %q", after.Subject.CommonName)
	}

	serial := after.SerialNumber.String()
	if err := EnsureCertificate(cert, key, nil); err != nil {
		t.Fatalf("повторный вызов: %v", err)
	}
	if readLeaf(t, cert).SerialNumber.String() != serial {
		t.Fatalf("нейтральная пара перевыпущена повторно — перевыпуск обязан быть однократным")
	}
}

func readLeaf(t *testing.T, certPath string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(certPath) //nolint:gosec
	if err != nil {
		t.Fatalf("чтение сертификата: %v", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatalf("сертификат не в формате PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("разбор сертификата: %v", err)
	}
	return leaf
}

func writeLegacyPair(t *testing.T, certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ключ: %v", err)
	}
	tpl := x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: legacyCommonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"vpn.lan", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("сертификат: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("ключ в DER: %v", err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("запись сертификата: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("запись ключа: %v", err)
	}
}
