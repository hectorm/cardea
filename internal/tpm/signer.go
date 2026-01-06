//go:build linux || windows

package tpm

import (
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
	tpm       transport.TPMCloser
	key       tpm2.AuthHandle
	sshPubKey ssh.PublicKey
	mu        sync.Mutex
	closed    bool
}

func NewBlobSigner(devicePath, blobPath string, opts *KeyOptions) (Signer, error) {
	if devicePath == "" {
		return nil, fmt.Errorf("tpm device path is required")
	}
	if blobPath == "" {
		return nil, fmt.Errorf("tpm blob path is required")
	}
	if opts == nil {
		opts = &KeyOptions{}
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

	var authHandle tpm2.AuthHandle
	var pubKey *ecdsa.PublicKey

	blobBytes, readErr := disk.ReadFile(blobPath)
	switch {
	case readErr == nil:
		blob, err := UnmarshalKeyBlob(blobBytes)
		if err != nil {
			_ = t.Close()
			return nil, fmt.Errorf("parse blob: %w", err)
		}

		authHandle, pubKey, err = loadKeyBlob(t, blob, opts)
		if err != nil {
			_ = t.Close()
			return nil, fmt.Errorf("load blob: %w", err)
		}
		slog.Debug("tpm key loaded", "blob", blobPath)
	case os.IsNotExist(readErr):
		var blob *KeyBlob
		blob, authHandle, pubKey, err = createKeyBlob(t, opts)
		if err != nil {
			_ = t.Close()
			return nil, fmt.Errorf("create blob: %w", err)
		}

		serialized, err := blob.Marshal()
		if err != nil {
			flushContext(t, authHandle.Handle)
			_ = t.Close()
			return nil, fmt.Errorf("marshal blob: %w", err)
		}

		if err := disk.WriteFile(blobPath, serialized, 0o600); err != nil {
			flushContext(t, authHandle.Handle)
			_ = t.Close()
			return nil, fmt.Errorf("write blob: %w", err)
		}
		slog.Debug("tpm key created", "blob", blobPath)
	default:
		_ = t.Close()
		return nil, fmt.Errorf("read blob: %w", readErr)
	}

	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		flushContext(t, authHandle.Handle)
		_ = t.Close()
		return nil, fmt.Errorf("ssh public key: %w", err)
	}

	blobSigner := &BlobSigner{
		tpm:       t,
		key:       authHandle,
		sshPubKey: sshPub,
	}

	return blobSigner, nil
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
	signCmd := tpm2.Sign{
		KeyHandle: s.key,
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

	sess := tpm2.HMAC(tpm2.TPMAlgSHA256, 20, tpm2.AESEncryption(128, tpm2.EncryptIn))
	resp, err := signCmd.Execute(s.tpm, sess)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	ecdsaSig, err := resp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, err
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
		s.key = tpm2.AuthHandle{}
	}

	return s.tpm.Close()
}
