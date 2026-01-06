package tpm

import (
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"
)

type Opener func(path string) (transport.TPMCloser, error)

type Signer interface {
	ssh.Signer
	io.Closer
}

type KeyOptions struct {
	ParentHandle tpm2.TPMHandle
	ParentAuth   []byte
	KeyAuth      []byte
	Opener       Opener
}

type KeyBlob struct {
	Private tpm2.TPM2BPrivate
	Public  tpm2.TPM2BPublic
	Name    tpm2.TPM2BName
}
