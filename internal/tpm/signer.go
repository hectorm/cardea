//go:build linux || windows

package tpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"

	"github.com/hectorm/cardea/internal/utils/disk"
)

var _ Signer = (*BlobSigner)(nil)

type BlobSigner struct {
	tpm          transport.TPMCloser
	key          tpm2.NamedHandle
	keyAuth      []byte
	srkHandle    tpm2.TPMHandle
	srkPub       tpm2.TPMTPublic
	srkTransient bool
	sshPubKey    ssh.PublicKey
	mu           sync.Mutex
	closed       bool
}

func NewBlobSigner(devicePath, blobPath string, opts *KeyOptions) (_ Signer, err error) {
	if devicePath == "" {
		return nil, fmt.Errorf("tpm device path is required")
	}
	if blobPath == "" {
		return nil, fmt.Errorf("tpm blob path is required")
	}
	if opts == nil {
		opts = &KeyOptions{}
	}
	if len(opts.KeyAuth) > sha256.Size {
		return nil, fmt.Errorf("tpm key auth must be at most %d bytes, got %d", sha256.Size, len(opts.KeyAuth))
	}
	if bytes.IndexByte(opts.KeyAuth, 0) != -1 {
		return nil, fmt.Errorf("tpm key auth must not contain NUL bytes")
	}
	if bytes.IndexByte(opts.ParentAuth, 0) != -1 {
		return nil, fmt.Errorf("tpm parent auth must not contain NUL bytes")
	}
	if len(opts.KeyAuth) == 0 {
		slog.Warn("tpm key auth is not set")
	}

	opener := opts.Opener
	if opener == nil {
		opener = DefaultOpener
	}

	t, err := opener(devicePath)
	if err != nil {
		return nil, fmt.Errorf("open tpm device: %w", err)
	}
	slog.Debug("tpm device opened", "device", devicePath)

	var signer *BlobSigner
	var srk srkContext
	var key tpm2.NamedHandle
	var pubKey *ecdsa.PublicKey

	defer func() {
		if err == nil {
			return
		}
		if signer != nil {
			_ = signer.Close()
			return
		}
		if key.Handle != 0 {
			flushContext(t, key.Handle)
		}
		if srk.transient {
			flushContext(t, srk.handle.Handle)
		}
		_ = t.Close()
	}()

	srk, err = getOrCreateSRK(t, opts)
	if err != nil {
		return nil, fmt.Errorf("prepare srk: %w", err)
	}

	blobBytes, readErr := disk.ReadFile(blobPath)
	switch {
	case readErr == nil:
		blob, err := UnmarshalKeyBlob(blobBytes)
		if err != nil {
			return nil, fmt.Errorf("parse blob: %w", err)
		}

		key, pubKey, err = loadKeyBlob(t, srk.handle, blob)
		if err != nil {
			return nil, fmt.Errorf("load blob: %w", err)
		}
		slog.Debug("tpm key loaded", "blob", blobPath)
	case os.IsNotExist(readErr):
		var blob *KeyBlob
		blob, key, pubKey, err = createKeyBlob(t, srk.handle, opts)
		if err != nil {
			return nil, fmt.Errorf("create blob: %w", err)
		}

		serialized, err := blob.Marshal()
		if err != nil {
			return nil, fmt.Errorf("marshal blob: %w", err)
		}

		if err := disk.WriteFile(blobPath, serialized, 0o600); err != nil {
			return nil, fmt.Errorf("write blob: %w", err)
		}
		slog.Debug("tpm key created", "blob", blobPath)
	default:
		return nil, fmt.Errorf("read blob: %w", readErr)
	}

	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("ssh public key: %w", err)
	}

	signer = &BlobSigner{
		tpm:          t,
		key:          key,
		keyAuth:      bytes.Clone(opts.KeyAuth),
		srkHandle:    srk.handle.Handle,
		srkPub:       srk.pub,
		srkTransient: srk.transient,
		sshPubKey:    sshPub,
	}

	probe := []byte("cardea tpm key self-test")
	sig, err := signer.Sign(nil, probe)
	if err != nil {
		return nil, fmt.Errorf("key self-test: %w", err)
	}
	if err := signer.sshPubKey.Verify(probe, sig); err != nil {
		return nil, fmt.Errorf("key self-test: %w", err)
	}

	return signer, nil
}

func (s *BlobSigner) PublicKey() ssh.PublicKey {
	return s.sshPubKey
}

func (s *BlobSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil, fmt.Errorf("signer closed")
	}

	digest := sha256.Sum256(data)
	keyHandle := tpm2.AuthHandle{
		Handle: s.key.Handle,
		Name:   s.key.Name,
		Auth:   keyAuthSession(s.srkHandle, s.srkPub, s.keyAuth),
	}
	signCmd := tpm2.Sign{
		KeyHandle: keyHandle,
		Digest:    tpm2.TPM2BDigest{Buffer: digest[:]},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgECDSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgECDSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}

	resp, err := signCmd.Execute(s.tpm)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	ecdsaSig, err := resp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("parse ecdsa signature: %w", err)
	}

	rInt := new(big.Int).SetBytes(ecdsaSig.SignatureR.Buffer)
	sInt := new(big.Int).SetBytes(ecdsaSig.SignatureS.Buffer)
	sig := &ssh.Signature{
		Format: s.sshPubKey.Type(),
		Blob:   ssh.Marshal(struct{ R, S *big.Int }{rInt, sInt}),
	}

	return sig, nil
}

func (s *BlobSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true

	if s.key.Handle != 0 {
		flushContext(s.tpm, s.key.Handle)
		s.key = tpm2.NamedHandle{}
	}

	if s.srkTransient && s.srkHandle != 0 {
		flushContext(s.tpm, s.srkHandle)
		s.srkHandle = 0
	}

	clear(s.keyAuth)

	return s.tpm.Close()
}
