//go:build windows

package tpm

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

func openTPM(_ string) (transport.TPMCloser, error) {
	return windowstpm.Open()
}
