package agentrpc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var ErrMessageTooLarge = errors.New("agentrpc: message exceeds size limit")

func readLine(r io.Reader) ([]byte, error) {

	br := bufio.NewReaderSize(io.LimitReader(r, MaxMessageSize+1), 64*1024)
	line, err := br.ReadBytes('\n')
	if err == nil {
		return bytes.TrimSuffix(line, []byte("\n")), nil
	}
	if errors.Is(err, io.EOF) && len(line) > MaxMessageSize {

		return nil, ErrMessageTooLarge
	}
	if len(line) > MaxMessageSize {
		return nil, ErrMessageTooLarge
	}
	return nil, err
}

func writeMessage(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("agentrpc: marshal: %w", err)
	}
	if len(payload)+1 > MaxMessageSize {
		return ErrMessageTooLarge
	}
	payload = append(payload, '\n')
	_, err = w.Write(payload)
	return err
}
