//go:build !linux && !windows

package tpm

import "fmt"

func NewBlobSigner(devicePath, blobPath string, opts *KeyOptions) (Signer, error) {
	return nil, fmt.Errorf("tpm is not supported on this platform")
}
