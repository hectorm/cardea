package credential

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/hectorm/cardea/internal/utils/disk"
)

var _ Provider = (*FileKeyProvider)(nil)

type FileKeyProvider struct {
	signer ssh.Signer
}

func NewFileKeyProvider(keyPath, passphrase string) (*FileKeyProvider, error) {
	keyPath = filepath.Clean(keyPath)

	var signer ssh.Signer
	var err error

	if _, statErr := os.Stat(keyPath); os.IsNotExist(statErr) {
		signer, err = createKey(keyPath, passphrase)
	} else if statErr == nil {
		signer, err = loadKey(keyPath, passphrase)
	} else {
		return nil, statErr
	}

	if err != nil {
		return nil, err
	}

	return &FileKeyProvider{signer: signer}, nil
}

func (p *FileKeyProvider) GetAuthMethod(ctx context.Context, user, host, port string) (ssh.AuthMethod, error) {
	return ssh.PublicKeys(p.signer), nil
}

func (p *FileKeyProvider) Signer() ssh.Signer {
	return p.signer
}

func (p *FileKeyProvider) PublicKey() ssh.PublicKey {
	return p.signer.PublicKey()
}

func (p *FileKeyProvider) Close() error {
	return nil
}

func createKey(keyPath, passphrase string) (ssh.Signer, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	var pemBlock *pem.Block
	if passphrase != "" {
		pemBlock, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, "", []byte(passphrase))
	} else {
		pemBlock, err = ssh.MarshalPrivateKey(privateKey, "")
	}
	if err != nil {
		return nil, err
	}

	if err := disk.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		return nil, err
	}

	return ssh.NewSignerFromKey(privateKey)
}

func loadKey(keyPath, passphrase string) (ssh.Signer, error) {
	pemBytes, err := disk.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
	}
	return ssh.ParsePrivateKey(pemBytes)
}
