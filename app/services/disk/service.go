package disk

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/vpn-vendor/vpn-panel-core/app/facades"
	"github.com/vpn-vendor/vpn-panel-core/internal/agentrpc"
	"github.com/vpn-vendor/vpn-panel-core/internal/diskcrypt"
)

type Service struct{}

func New() *Service { return &Service{} }

func (s *Service) client() *agentrpc.Client {
	return &agentrpc.Client{SocketPath: facades.Config().GetString("agent.socket")}
}

func (s *Service) Status() (*diskcrypt.Status, error) {
	return s.call("disk.status", map[string]any{})
}

func (s *Service) RequestChange(on bool) (*diskcrypt.Status, error) {
	return s.call("disk.change_request", map[string]any{"requested": on})
}

func (s *Service) call(method string, params any) (*diskcrypt.Status, error) {
	resp, err := s.client().Call(method, params)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, resp.Error
	}
	var st diskcrypt.Status
	if err := json.Unmarshal(resp.Result, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func CipherText(st diskcrypt.Status) string {
	switch {
	case strings.HasPrefix(st.Cipher, "aes-xts"):

		return "AES-" + strconv.Itoa(st.KeyBits/2) + ", с ускорением процессора"
	case strings.Contains(st.Cipher, "adiantum"):
		return "Adiantum-" + strconv.Itoa(st.KeyBits) + " — у процессора нет ускорения AES, этот шифр для него быстрее"
	default:
		return "шифр, выбранный при установке"
	}
}

func LastChangeText(st diskcrypt.Status) (text string, warn bool) {
	switch st.LastChange {
	case "changed":
		return "Последняя смена пароля прошла успешно.", false
	case "skipped":
		return "При последнем включении смену пароля пропустили — действует прежний пароль.", false
	case "gave_up":
		return "При последнем включении текущий пароль трижды не подошёл — смена отменена, действует прежний пароль. Если это были не вы, смените пароль.", true
	case "failed":
		return "Последняя смена пароля не завершилась. Диск открывается прежним или новым паролем, смена повторится при следующем включении.", true
	}
	return "", false
}
