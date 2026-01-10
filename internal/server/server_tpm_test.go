//go:build (linux || windows) && cgo

package server

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2/transport"
	"golang.org/x/crypto/ssh"

	"github.com/hectorm/cardea/internal/credential"
	"github.com/hectorm/cardea/internal/server/mock"
	"github.com/hectorm/cardea/internal/tpm"
)

type simulatorTransport struct {
	sim *simulator.Simulator
}

func (s *simulatorTransport) Send(input []byte) ([]byte, error) {
	if _, err := s.sim.Write(input); err != nil {
		return nil, err
	}
	resp := make([]byte, 4096)
	n, err := s.sim.Read(resp)
	if err != nil {
		return nil, err
	}
	return resp[:n], nil
}

func (s *simulatorTransport) Close() error {
	return s.sim.Close()
}

func simulatorOpener() tpm.Opener {
	return func(_ string) (transport.TPMCloser, error) {
		sim, err := simulator.Get()
		if err != nil {
			return nil, err
		}
		return &simulatorTransport{sim: sim}, nil
	}
}

func TestBastionSSHServerTPM(t *testing.T) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	opener := simulatorOpener()

	t.Run("credential_providers", func(t *testing.T) {
		t.Run("tpm", func(t *testing.T) {
			t.Run("blob_serialization", func(t *testing.T) {
				original := &tpm.KeyBlob{}

				serialized, err := original.Marshal()
				if err != nil {
					t.Errorf("failed to marshal key blob: %v", err)
					return
				}

				restored, err := tpm.UnmarshalKeyBlob(serialized)
				if err != nil {
					t.Errorf("failed to unmarshal key blob: %v", err)
					return
				}

				reserialized, err := restored.Marshal()
				if err != nil {
					t.Errorf("failed to re-marshal key blob: %v", err)
					return
				}

				if !bytes.Equal(serialized, reserialized) {
					t.Error("round-trip serialization mismatch")
					return
				}

				for _, data := range [][]byte{
					{},
					{0x01, 0x02},
					[]byte("XXXX\x00\x01"),
					[]byte("CTK\x00\x00\x63"),
					[]byte("CTK\x00\x00\x01\x00\x10"),
				} {
					if _, err := tpm.UnmarshalKeyBlob(data); err == nil {
						t.Errorf("expected unmarshal to fail for data %x", data)
					}
				}
			})

			t.Run("blob_signer_operations", func(t *testing.T) {
				corruptedPath := filepath.Join(t.TempDir(), "corrupted.blob")
				_ = os.WriteFile(corruptedPath, []byte("CTK\x00\x00\x01corrupted"), 0o600)
				if _, err := tpm.NewBlobSigner("simulator", corruptedPath, &tpm.KeyOptions{Opener: opener}); err == nil {
					t.Error("expected NewBlobSigner with corrupted blob to fail")
				}

				openerCalled := false
				blobPath := filepath.Join(t.TempDir(), "test.blob")
				keyOpts := &tpm.KeyOptions{
					KeyAuth: []byte("test-auth"),
					Opener: func(path string) (transport.TPMCloser, error) {
						openerCalled = true
						return opener(path)
					},
				}
				signer, err := tpm.NewBlobSigner("simulator", blobPath, keyOpts)
				if err != nil {
					t.Errorf("failed to create blob signer: %v", err)
					return
				}
				if !openerCalled {
					t.Error("expected custom opener to be called")
					return
				}

				sig, err := signer.Sign(nil, []byte("test data"))
				if err != nil {
					t.Errorf("failed to sign data: %v", err)
					return
				}
				if sig.Format != "ecdsa-sha2-nistp256" || len(sig.Blob) == 0 {
					t.Errorf("unexpected signature: format=%q, blob_len=%d", sig.Format, len(sig.Blob))
					return
				}

				if _, err := signer.Sign(nil, []byte("more data")); err != nil {
					t.Errorf("failed to sign data second time: %v", err)
					return
				}

				_ = signer.PublicKey()

				_ = signer.Close()
				if _, err := signer.Sign(nil, []byte("x")); err == nil || !strings.Contains(err.Error(), "closed") {
					t.Error("expected sign after close to fail with 'closed' error")
					return
				}

				if err := signer.Close(); err != nil {
					t.Errorf("expected double close to succeed: %v", err)
					return
				}
			})

			t.Run("provider", func(t *testing.T) {
				blobPath := filepath.Join(t.TempDir(), "test.blob")
				keyOpts := &tpm.KeyOptions{
					KeyAuth: []byte("test-auth"),
					Opener:  opener,
				}
				provider, err := credential.NewTPMKeyProvider("simulator", blobPath, keyOpts)
				if err != nil {
					t.Errorf("failed to create key provider: %v", err)
					return
				}
				defer func() { _ = provider.Close() }()

				publicKey := provider.PublicKey()
				if publicKey == nil || publicKey.Type() != "ecdsa-sha2-nistp256" {
					t.Errorf("unexpected public key: %v", publicKey)
					return
				}

				authMethod, err := provider.GetAuthMethod(t.Context(), "user", "host", "22")
				if err != nil || authMethod == nil {
					t.Errorf("failed to get auth method: %v", err)
					return
				}

				bastionPubKeyStr := marshalAuthorizedKey(provider.PublicKey())
				mockSrv, err := setupMockServer(t, mock.WithPublicKeyCallback(func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					if marshalAuthorizedKey(key) == bastionPubKeyStr {
						return &ssh.Permissions{}, nil
					}
					return nil, fmt.Errorf("denied")
				}))
				if err != nil {
					t.Errorf("failed to setup mock server: %v", err)
					return
				}
				mockAddr := mockSrv.Address()
				mockAuthorizedKeyStr := marshalAuthorizedKey(mockSrv.Signer().PublicKey())

				cli, cliPublicKey, err := setupClient(t)
				if err != nil {
					t.Errorf("failed to setup client: %v", err)
					return
				}
				cli.User = fmt.Sprintf("alice@%s", mockAddr)
				cliAuthorizedKeyStr := marshalAuthorizedKey(cliPublicKey)

				bastionSrv, err := setupBastionServer(t,
					fmt.Sprintf(`permitconnect="alice@%s" %s`, mockAddr, cliAuthorizedKeyStr),
					fmt.Sprintf("%s %s", mockAddr, mockAuthorizedKeyStr),
					WithCredentialProvider(provider),
				)
				if err != nil {
					t.Errorf("failed to setup bastion server: %v", err)
					return
				}

				bastionConn, err := connectToServer(t, cli, bastionSrv)
				if err != nil {
					t.Errorf("failed to connect to server: %v", err)
					return
				}

				session, err := bastionConn.NewSession()
				if err != nil {
					t.Errorf("failed to create session: %v", err)
					return
				}
				defer func() { _ = session.Close() }()

				if output, err := session.Output("echo Hello, World!"); err != nil {
					t.Errorf("failed to execute command: %v", err)
					return
				} else if expectedOutput := "Hello, World!\r\n"; string(output) != expectedOutput {
					t.Errorf("unexpected output: got %q, want %q", string(output), expectedOutput)
					return
				}
			})
		})
	})
}
