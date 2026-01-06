package credential

import (
	"context"

	"golang.org/x/crypto/ssh"
)

type Provider interface {
	GetAuthMethod(ctx context.Context, user, host, port string) (ssh.AuthMethod, error)

	Signer() ssh.Signer

	PublicKey() ssh.PublicKey

	Close() error
}
