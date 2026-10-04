package backupcrypt

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

var ErrWrongPassword = errors.New("пароль не подошёл, или файл копии изменён после создания")

var ErrTooLarge = errors.New("копия настроек больше допустимого размера")

func Encrypt(plain []byte, password string) ([]byte, error) {
	r, err := age.NewScryptRecipient(password)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plain); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func Decrypt(cipher []byte, password string, limit int64) ([]byte, error) {
	id, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(cipher), id)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWrongPassword, err)
	}
	plain, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWrongPassword, err)
	}
	if int64(len(plain)) > limit {
		return nil, ErrTooLarge
	}
	return plain, nil
}
