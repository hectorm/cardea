package credential

import (
	"context"

	"golang.org/x/crypto/ssh"

	"github.com/hectorm/cardea/internal/tpm"
)

var _ Provider = (*TPMKeyProvider)(nil)

type TPMKeyProvider struct {
	signer tpm.Signer
}

func NewTPMKeyProvider(devicePath, blobPath string, opts *tpm.KeyOptions) (*TPMKeyProvider, error) {
	signer, err := tpm.NewBlobSigner(devicePath, blobPath, opts)
	if err != nil {
		return nil, err
	}

	return &TPMKeyProvider{signer: signer}, nil
}

func (p *TPMKeyProvider) GetAuthMethod(ctx context.Context, user, host, port string) (ssh.AuthMethod, error) {
	return ssh.PublicKeys(p.signer), nil
}

func (p *TPMKeyProvider) Signer() ssh.Signer {
	return p.signer
}

func (p *TPMKeyProvider) PublicKey() ssh.PublicKey {
	return p.signer.PublicKey()
}

func (p *TPMKeyProvider) Close() error {
	return p.signer.Close()
}
