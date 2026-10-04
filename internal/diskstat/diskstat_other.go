//go:build !linux

package diskstat

import "errors"

func Usage(string) (Space, error) { return Space{}, errors.New("diskstat: only linux") }
