//go:build linux

package tpm

import (
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

func openTPM(devicePath string) (transport.TPMCloser, error) {
	if info, err := os.Stat(devicePath); err == nil {
		if info.Mode()&os.ModeSocket != 0 {
			return linuxudstpm.Open(devicePath)
		}
	}
	return linuxtpm.Open(devicePath)
}
