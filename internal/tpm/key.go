//go:build linux || windows

package tpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"strconv"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

var DefaultOpener Opener = openTPM

func ParseParentHandle(s string) (tpm2.TPMHandle, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	s = strings.ToLower(s)
	if !strings.HasPrefix(s, "0x") {
		return 0, fmt.Errorf("invalid parent handle %q: must be a hex handle (e.g. 0x81000001)", s)
	}

	val, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid parent handle %q: %w", s, err)
	}

	handle := tpm2.TPMHandle(val)
	if (handle & 0xFF000000) != 0x81000000 {
		return 0, fmt.Errorf("invalid parent handle 0x%x: must be a persistent handle (0x81xxxxxx)", handle)
	}

	return handle, nil
}

const (
	blobMagic   = "CTK\x00"
	blobVersion = uint16(1)
)

func (b *KeyBlob) Marshal() ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString(blobMagic)
	if err := binary.Write(&buf, binary.BigEndian, blobVersion); err != nil {
		return nil, fmt.Errorf("write version: %w", err)
	}

	chunks := [][]byte{
		tpm2.Marshal(b.Private),
		tpm2.Marshal(b.Public),
		tpm2.Marshal(b.Name),
	}
	for _, chunk := range chunks {
		if err := writeChunk(&buf, chunk); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func UnmarshalKeyBlob(data []byte) (*KeyBlob, error) {
	r := bytes.NewReader(data)

	magic := make([]byte, len(blobMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return nil, fmt.Errorf("truncated key blob")
	}
	if string(magic) != blobMagic {
		return nil, fmt.Errorf("invalid key blob header")
	}

	var version uint16
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return nil, fmt.Errorf("truncated key blob")
	}
	if version != blobVersion {
		return nil, fmt.Errorf("unsupported key blob version: got %d, expected %d", version, blobVersion)
	}

	privBytes, err := readChunk(r)
	if err != nil {
		return nil, err
	}
	pubBytes, err := readChunk(r)
	if err != nil {
		return nil, err
	}
	nameBytes, err := readChunk(r)
	if err != nil {
		return nil, err
	}

	if r.Len() != 0 {
		return nil, fmt.Errorf("key blob has trailing data")
	}

	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](privBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal private: %w", err)
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](pubBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal public: %w", err)
	}
	name, err := tpm2.Unmarshal[tpm2.TPM2BName](nameBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal name: %w", err)
	}

	blob := &KeyBlob{
		Private: *priv,
		Public:  *pub,
		Name:    *name,
	}

	return blob, nil
}

func writeChunk(w io.Writer, data []byte) error {
	len := len(data)
	if len > math.MaxUint16 {
		return fmt.Errorf("key blob chunk too large: %d bytes", len)
	}
	if err := binary.Write(w, binary.BigEndian, uint16(len)); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

func readChunk(r io.Reader) ([]byte, error) {
	var length uint16
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("truncated key blob")
	}
	chunk := make([]byte, length)
	if _, err := io.ReadFull(r, chunk); err != nil {
		return nil, fmt.Errorf("truncated key blob")
	}
	return chunk, nil
}

func createKeyBlob(t transport.TPM, opts *KeyOptions) (*KeyBlob, tpm2.AuthHandle, *ecdsa.PublicKey, error) {
	if opts == nil {
		opts = &KeyOptions{}
	}

	srk, srkPub, needsFlush, err := getOrCreateSRK(t, opts)
	if err != nil {
		return nil, tpm2.AuthHandle{}, nil, err
	}
	if needsFlush {
		defer flushContext(t, srk.Handle)
	}

	createCmd := tpm2.Create{
		ParentHandle: srk,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{Buffer: opts.KeyAuth},
			},
		},
		InPublic: tpm2.New2B(ecdsaP256Template),
	}
	createResp, err := createCmd.Execute(t, hmacSession(srk.Handle, srkPub))
	if err != nil {
		return nil, tpm2.AuthHandle{}, nil, err
	}

	loadCmd := tpm2.Load{
		ParentHandle: srk,
		InPrivate:    createResp.OutPrivate,
		InPublic:     createResp.OutPublic,
	}
	loadResp, err := loadCmd.Execute(t, hmacSession(srk.Handle, srkPub))
	if err != nil {
		return nil, tpm2.AuthHandle{}, nil, err
	}

	pubKey, err := extractECDSAPublicKey(createResp.OutPublic)
	if err != nil {
		flushContext(t, loadResp.ObjectHandle)
		return nil, tpm2.AuthHandle{}, nil, err
	}

	keyBlob := &KeyBlob{
		Private: createResp.OutPrivate,
		Public:  createResp.OutPublic,
		Name:    loadResp.Name,
	}

	authHandle := tpm2.AuthHandle{
		Handle: loadResp.ObjectHandle,
		Name:   loadResp.Name,
		Auth:   tpm2.PasswordAuth(opts.KeyAuth),
	}

	return keyBlob, authHandle, pubKey, nil
}

func loadKeyBlob(t transport.TPM, blob *KeyBlob, opts *KeyOptions) (tpm2.AuthHandle, *ecdsa.PublicKey, error) {
	if blob == nil {
		return tpm2.AuthHandle{}, nil, fmt.Errorf("key blob is nil")
	}
	if opts == nil {
		opts = &KeyOptions{}
	}

	srk, srkPub, needsFlush, err := getOrCreateSRK(t, opts)
	if err != nil {
		return tpm2.AuthHandle{}, nil, err
	}
	if needsFlush {
		defer flushContext(t, srk.Handle)
	}

	loadCmd := tpm2.Load{
		ParentHandle: srk,
		InPrivate:    blob.Private,
		InPublic:     blob.Public,
	}
	loadResp, err := loadCmd.Execute(t, hmacSession(srk.Handle, srkPub))
	if err != nil {
		return tpm2.AuthHandle{}, nil, err
	}

	if len(blob.Name.Buffer) == 0 {
		flushContext(t, loadResp.ObjectHandle)
		return tpm2.AuthHandle{}, nil, fmt.Errorf("key blob missing name")
	}
	if !bytes.Equal(blob.Name.Buffer, loadResp.Name.Buffer) {
		flushContext(t, loadResp.ObjectHandle)
		return tpm2.AuthHandle{}, nil, fmt.Errorf("key blob name mismatch")
	}

	pubKey, err := extractECDSAPublicKey(blob.Public)
	if err != nil {
		flushContext(t, loadResp.ObjectHandle)
		return tpm2.AuthHandle{}, nil, err
	}

	authHandle := tpm2.AuthHandle{
		Handle: loadResp.ObjectHandle,
		Name:   loadResp.Name,
		Auth:   tpm2.PasswordAuth(opts.KeyAuth),
	}

	return authHandle, pubKey, nil
}

var (
	srkTemplate = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			FirmwareLimited:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           true,
			Decrypt:              true,
			SignEncrypt:          false,
			X509Sign:             false,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: nil},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
				},
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgNull,
				},
				CurveID: tpm2.TPMECCNistP256,
				KDF: tpm2.TPMTKDFScheme{
					Scheme: tpm2.TPMAlgNull,
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 0)},
				Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 0)},
			},
		),
	}
	ecdsaP256Template = tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			STClear:              false,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			AdminWithPolicy:      false,
			FirmwareLimited:      false,
			NoDA:                 true,
			EncryptedDuplication: false,
			Restricted:           false,
			Decrypt:              false,
			SignEncrypt:          true,
			X509Sign:             false,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: nil},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgNull,
				},
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
				KDF: tpm2.TPMTKDFScheme{
					Scheme: tpm2.TPMAlgNull,
				},
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 0)},
				Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 0)},
			},
		),
	}
)

func getOrCreateSRK(t transport.TPM, opts *KeyOptions) (tpm2.AuthHandle, tpm2.TPMTPublic, bool, error) {
	var parentHandle tpm2.TPMHandle
	var parentAuth []byte

	if opts != nil {
		parentHandle = opts.ParentHandle
		parentAuth = opts.ParentAuth
	}

	if parentHandle != 0 {
		readPub := tpm2.ReadPublic{ObjectHandle: parentHandle}
		resp, err := readPub.Execute(t)
		if err != nil {
			return tpm2.AuthHandle{}, tpm2.TPMTPublic{}, false, fmt.Errorf("persistent key 0x%x not found: %w", parentHandle, err)
		}

		srkPub, err := resp.OutPublic.Contents()
		if err != nil {
			return tpm2.AuthHandle{}, tpm2.TPMTPublic{}, false, fmt.Errorf("parse srk public: %w", err)
		}

		slog.Debug("using persistent srk", "handle", parentHandle)
		authHandle := tpm2.AuthHandle{
			Handle: parentHandle,
			Name:   resp.Name,
			Auth:   tpm2.PasswordAuth(parentAuth),
		}

		return authHandle, *srkPub, false, nil
	}

	createPrimaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(parentAuth),
		},
		InPublic: tpm2.New2B(srkTemplate),
	}

	resp, err := createPrimaryCmd.Execute(t)
	if err != nil {
		return tpm2.AuthHandle{}, tpm2.TPMTPublic{}, false, fmt.Errorf("create transient srk: %w (check owner password)", err)
	}

	srkPub, err := resp.OutPublic.Contents()
	if err != nil {
		flushContext(t, resp.ObjectHandle)
		return tpm2.AuthHandle{}, tpm2.TPMTPublic{}, false, fmt.Errorf("parse srk public: %w", err)
	}

	slog.Debug("created transient srk", "handle", resp.ObjectHandle)
	authHandle := tpm2.AuthHandle{
		Handle: resp.ObjectHandle,
		Name:   resp.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}

	return authHandle, *srkPub, true, nil
}

func hmacSession(srkHandle tpm2.TPMHandle, srkPub tpm2.TPMTPublic) tpm2.Session {
	return tpm2.HMAC(
		tpm2.TPMAlgSHA256,
		20,
		tpm2.AESEncryption(128, tpm2.EncryptInOut),
		tpm2.Salted(srkHandle, srkPub),
	)
}

func extractECDSAPublicKey(pubTpm tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	pubContents, err := pubTpm.Contents()
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	eccParms, err := pubContents.Parameters.ECCDetail()
	if err != nil {
		return nil, fmt.Errorf("get ecc parameters: %w", err)
	}

	var curve elliptic.Curve
	switch eccParms.CurveID {
	case tpm2.TPMECCNistP256:
		curve = elliptic.P256()
	default:
		return nil, fmt.Errorf("unsupported elliptic curve: %v", eccParms.CurveID)
	}

	eccUnique, err := pubContents.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("get ecc unique: %w", err)
	}

	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(eccUnique.X.Buffer),
		Y:     new(big.Int).SetBytes(eccUnique.Y.Buffer),
	}

	return pubKey, nil
}

func flushContext(t transport.TPM, handle tpm2.TPMHandle) {
	flushCmd := tpm2.FlushContext{FlushHandle: handle}
	_, _ = flushCmd.Execute(t)
}
