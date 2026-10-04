package agentrpc

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const Version = "2.0"

const MaxMessageSize = 1 << 20

const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603

	CodeForbidden = -32001
)

type Request struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *ErrorObject    `json:"error,omitempty"`
}

type ErrorObject struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

func (e *ErrorObject) Error() string {
	return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message)
}

const (
	dataRecoverable = "recoverable"
	dataRetryAfter  = "retry_after_sec"
)

func Busy(code int, message string, wait time.Duration) *ErrorObject {
	sec := int64((wait + time.Second - 1) / time.Second)
	if sec < 1 {
		sec = 1
	}
	return &ErrorObject{Code: code, Message: message,
		Data: map[string]any{dataRecoverable: true, dataRetryAfter: sec}}
}

func (e *ErrorObject) Recoverable() bool {
	v, _ := e.Data[dataRecoverable].(bool)
	return v
}

func (e *ErrorObject) RetryAfter() (time.Duration, bool) {
	var sec float64
	switch v := e.Data[dataRetryAfter].(type) {
	case float64:
		sec = v
	case int64:
		sec = float64(v)
	case int:
		sec = float64(v)
	default:
		return 0, false
	}
	if sec <= 0 {
		return 0, false
	}
	return time.Duration(sec * float64(time.Second)), true
}

type TransportError struct {
	Op  string
	Err error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("agent transport error (%s): %v", e.Op, e.Err)
}

func (e *TransportError) Unwrap() error { return e.Err }

func Human(err error) string {
	var terr *TransportError
	if errors.As(err, &terr) {
		return "Системная служба недоступна — попробуйте позже."
	}
	var merr *ErrorObject
	if errors.As(err, &merr) {
		if merr.Code < 0 {
			return "Внутренняя ошибка системной службы — обратитесь в поддержку."
		}
		return merr.Message
	}
	if err != nil {
		return err.Error()
	}
	return ""
}
