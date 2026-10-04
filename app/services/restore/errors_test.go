package restore

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/backupfile"
)

func TestTextIsHuman(t *testing.T) {
	agent := &agentrpc.ErrorObject{Code: 2105, Message: "пароль не подошёл или файл изменён"}
	for _, c := range []struct {
		err  error
		want string
	}{
		{refuse("импорт не удался и откачен", agent), "импорт не удался и откачен: пароль не подошёл или файл изменён"},
		{fmt.Errorf("%w: unexpected end of JSON input", backupfile.ErrMalformed), backupfile.ErrMalformed.Error()},
		{ErrPending, ErrPending.Error()},
		{errors.New("open /var/lib/x: permission denied"), generic},
	} {
		got := Text(c.err)
		if got != c.want || strings.Contains(got, "jsonrpc") {
			t.Errorf("%v → %q, ждали %q", c.err, got, c.want)
		}
	}
}
