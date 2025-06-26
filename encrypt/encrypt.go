package encrypt

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/compression/zip"
	"github.com/namelesscorp/tvault-core/container"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/integrity/hmac"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/shamir"
	"github.com/namelesscorp/tvault-core/token"
)

const (
	TokenSaveTypeFile   = "file"
	TokenSaveTypeStdout = "stdout"
)

var (
	compressionTypes = map[string]struct{}{
		compression.TypeNameZip: {},
	}
	tokenSaveTypes = map[string]struct{}{
		TokenSaveTypeFile:   {},
		TokenSaveTypeStdout: {},
	}
	integrityTypes = map[string]struct{}{
		integrity.TypeNameNone: {},
		integrity.TypeNameHMAC: {},
	}

	ErrUnknownCompressionType       = errors.New("unknown compression type")
	ErrNoneCompressionUnimplemented = errors.New("compression type none unimplemented")
	ErrUnknownIntegrityProvider     = errors.New("unknown integrity provider")
	ErrEd25519Unimplemented         = errors.New("integrity provider ed25519 unimplemented")

	ErrContainerPathRequired = errors.New("container-path is required")
	ErrFolderPathRequired    = errors.New("folder-path is required")
	ErrPassphraseRequired    = errors.New("passphrase is required")
	ErrInvalidCompression    = errors.New("compression-type must be [zip]")
	ErrInvalidTokenSave      = errors.New("token-save-type must be [file | stdout]")
	ErrInvalidIntegrity      = errors.New("integrity-provider must be [none | hmac ]")
	ErrMissingPassword       = errors.New("additional-password is required for -integrity-provider=hmac")
	ErrMissingKeyPath        = errors.New("key-save-path is required for -key-save-type=[file]")
)

type Options struct {
	ContainerPath      *string
	FolderPath         *string
	CompressionType    *string
	Passphrase         *string
	TokenSaveType      *string
	TokenSavePath      *string
	NumberOfShares     *int
	Threshold          *int
	IntegrityProvider  *string
	AdditionalPassword *string
	IsShamirEnabled    *bool
}

func (o *Options) Validate() error {
	if *o.ContainerPath == "" {
		return ErrContainerPathRequired
	}
	if *o.FolderPath == "" {
		return ErrFolderPathRequired
	}
	if *o.Passphrase == "" {
		return ErrPassphraseRequired
	}
	if _, ok := compressionTypes[*o.CompressionType]; !ok {
		return ErrInvalidCompression
	}
	if _, ok := tokenSaveTypes[*o.TokenSaveType]; !ok {
		return ErrInvalidTokenSave
	}
	if _, ok := integrityTypes[*o.IntegrityProvider]; !ok {
		return ErrInvalidIntegrity
	}
	if *o.AdditionalPassword == "" && *o.IntegrityProvider == integrity.TypeNameHMAC {
		return ErrMissingPassword
	}
	if *o.TokenSavePath == "" && *o.TokenSaveType == TokenSaveTypeFile {
		return ErrMissingKeyPath
	}
	return nil
}

func Encrypt(options Options) error {
	// compressing folder and getting data, compression
	data, compID, err := compressFolder(options)
	if err != nil {
		return err
	}

	// create container and get master key and container salt
	masterKey, containerSalt, err := createContainer(options, data, compID)
	if err != nil {
		return err
	}

	integrityProvider, err := createIntegrityProvider(options)
	if err != nil {
		return err
	}

	additionalPassword, err := deriveAdditionalPassword(options, containerSalt)
	if err != nil {
		return err
	}

	return generateAndSaveTokens(options, additionalPassword, masterKey, integrityProvider)
}

func compressFolder(options Options) ([]byte, byte, error) {
	switch *options.CompressionType {
	case compression.TypeNameZip:
		comp := zip.New()
		data, err := comp.Pack(*options.FolderPath)
		if err != nil {
			return nil, 0, fmt.Errorf("compression pack error; %w", err)
		}

		return data, comp.ID(), nil
	case compression.TypeNameNone:
		return nil, 0, ErrNoneCompressionUnimplemented
	default:
		return nil, 0, ErrUnknownCompressionType
	}
}

func createContainer(options Options, data []byte, compressionID byte) ([]byte, []byte, error) {
	cont := container.NewContainer(*options.ContainerPath, container.Metadata{
		CreatedAt: time.Now(),
		Comment:   "created by tvault-core",
	})

	masterKey, err := cont.Create(data, []byte(*options.Passphrase), compressionID)
	if err != nil {
		return nil, nil, fmt.Errorf("create container error; %w", err)
	}

	var containerHeaderSalt = cont.GetHeader().Salt

	return masterKey, containerHeaderSalt[:], nil
}

func createIntegrityProvider(options Options) (integrity.Provider, error) {
	switch *options.IntegrityProvider {
	case integrity.TypeNameNone:
		return integrity.NewNoneProvider(), nil
	case integrity.TypeNameHMAC:
		return hmac.New([]byte(*options.AdditionalPassword)), nil
	case integrity.TypeNameEd25519:
		return nil, ErrEd25519Unimplemented
	default:
		return nil, ErrUnknownIntegrityProvider
	}
}

func deriveAdditionalPassword(options Options, salt []byte) ([]byte, error) {
	if *options.AdditionalPassword != "" && *options.IntegrityProvider == integrity.TypeNameHMAC {
		return lib.PBKDF2Key(
			[]byte(*options.AdditionalPassword),
			salt,
			lib.Iterations,
			lib.KeyLen,
		), nil
	}

	return nil, nil
}

func generateAndSaveTokens(
	options Options,
	additionalPassword []byte,
	masterKey []byte,
	integrityProvider integrity.Provider,
) error {
	tokenWriter, closer, err := getTokenWriter(options)
	if err != nil {
		return err
	}
	if closer != nil {
		defer closeWithErrorLog(closer)
	}

	if *options.IsShamirEnabled {
		return generateAndSaveShareTokens(options, additionalPassword, masterKey, integrityProvider, tokenWriter)
	}

	return generateAndSaveMasterToken(additionalPassword, masterKey, tokenWriter)
}

func getTokenWriter(options Options) (io.Writer, io.Closer, error) {
	if *options.TokenSaveType == TokenSaveTypeFile {
		file, err := os.Create(*options.TokenSavePath)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create token file; %w", err)
		}

		return file, file, nil
	}

	return stdoutWriter{}, nil, nil
}

type stdoutWriter struct{}

func (w stdoutWriter) Write(p []byte) (n int, err error) {
	fmt.Print(string(p))
	return len(p), nil
}

func closeWithErrorLog(closer io.Closer) {
	if err := closer.Close(); err != nil {
		log.Printf("error closing file: %v", err)
	}
}

type tokenList struct {
	ShareList map[int]string `json:"share_list"`
}

func generateAndSaveShareTokens(
	options Options,
	additionalPassword []byte,
	masterKey []byte,
	integrity integrity.Provider,
	writer io.Writer,
) error {
	shares, err := shamir.Split(
		masterKey,
		*options.NumberOfShares,
		*options.Threshold,
		integrity,
	)
	if err != nil {
		return fmt.Errorf("shamir split error; %w", err)
	}

	var jsonTokenList = tokenList{
		ShareList: make(map[int]string, len(shares)),
	}
	for _, share := range shares {
		var shareToken []byte
		if shareToken, err = token.Build(
			token.Token{
				Version:    token.Version,
				ID:         int(share.ID),
				Type:       int(token.TypeShare),
				Value:      hex.EncodeToString(share.Value),
				Signature:  hex.EncodeToString(share.Signature),
				ProviderID: int(share.ProviderID),
			},
			additionalPassword,
		); err != nil {
			return fmt.Errorf("build token (shares) error; %w", err)
		}

		jsonTokenList.ShareList[int(share.ID)] = base64.StdEncoding.EncodeToString(shareToken)
	}

	var bytesTokenList []byte
	if bytesTokenList, err = json.MarshalIndent(jsonTokenList, "", " "); err != nil {
		return fmt.Errorf("marshal token list error; %w", err)
	}

	if _, err = writer.Write(bytesTokenList); err != nil {
		return fmt.Errorf("failed to write share token; %w", err)
	}

	return nil
}

type masterToken struct {
	MasterToken string `json:"master_token"`
}

func generateAndSaveMasterToken(
	additionalPassword []byte,
	masterKey []byte,
	writer io.Writer,
) error {
	newMasterToken, err := token.Build(
		token.Token{
			Version:    token.Version,
			Type:       int(token.TypeMaster),
			Value:      hex.EncodeToString(masterKey),
			ProviderID: int(integrity.TypeNone),
		},
		additionalPassword,
	)
	if err != nil {
		return fmt.Errorf("build token (master) error; %w", err)
	}

	var bytesMasterToken []byte
	if bytesMasterToken, err = json.MarshalIndent(
		masterToken{
			MasterToken: base64.StdEncoding.EncodeToString(newMasterToken),
		}, "", " ",
	); err != nil {
		return fmt.Errorf("marshal token list error; %w", err)
	}

	if _, err = writer.Write(bytesMasterToken); err != nil {
		return fmt.Errorf("failed to write master token; %w", err)
	}

	return nil
}
