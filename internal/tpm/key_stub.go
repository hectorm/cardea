//go:build !linux && !windows

package tpm

import (
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

func ParseParentHandle(s string) (tpm2.TPMHandle, error) {
	return tpm2.TPMHandle(0), fmt.Errorf("tpm is not supported on this platform")
}
