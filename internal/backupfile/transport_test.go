package backupfile_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupcrypt"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

func TestMaxCopyFitsSocketLine(t *testing.T) {
	c, err := backupcrypt.Encrypt(bytes.Repeat([]byte("x"), backupfile.MaxBytes), "пароль-копии-длинный")
	if err != nil {
		t.Fatal(err)
	}
	result, _ := json.Marshal(map[string]any{
		"file":    base64.StdEncoding.EncodeToString(c),
		"secrets": map[string]any{"wireguard": []string{"профиль"}},
	})
	line, _ := json.Marshal(agentrpc.Response{Jsonrpc: agentrpc.Version, ID: 1, Result: result})
	if len(line)+1 > agentrpc.MaxMessageSize {
		t.Fatalf("копия предельного размера — %d байт, строка сокета — %d", len(line)+1, agentrpc.MaxMessageSize)
	}
}
