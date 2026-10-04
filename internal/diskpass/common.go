package diskpass

import (
	"bytes"
	"compress/gzip"
	_ "embed"
)

//go:embed common-passwords.gz
var commonGz []byte

func Builtin(context ...string) (*Policy, error) {
	zr, err := gzip.NewReader(bytes.NewReader(commonGz))
	if err != nil {
		return nil, err
	}
	p, err := NewPolicy(zr, context...)

	if cerr := zr.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}
