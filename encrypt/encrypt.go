package encrypt

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
		return &lib.Error{
			Message: lib.ErrContainerPathRequired,
			Code:    0x101,
			Type:    lib.ValidationErrorType,
		}
	}
	if *o.FolderPath == "" {
		return &lib.Error{
			Message: lib.ErrFolderPathRequired,
			Code:    0x102,
			Type:    lib.ValidationErrorType,
		}
	}
	if *o.Passphrase == "" {
		return &lib.Error{
			Message: lib.ErrPassphraseRequired,
			Code:    0x103,
			Type:    lib.ValidationErrorType,
		}
	}
	if _, ok := compressionTypes[*o.CompressionType]; !ok {
		return &lib.Error{
			Message: lib.ErrInvalidCompression,
			Code:    0x104,
			Type:    lib.ValidationErrorType,
		}
	}
	if _, ok := tokenSaveTypes[*o.TokenSaveType]; !ok {
		return &lib.Error{
			Message: lib.ErrInvalidTokenSave,
			Code:    0x105,
			Type:    lib.ValidationErrorType,
		}
	}
	if _, ok := integrityTypes[*o.IntegrityProvider]; !ok {
		return &lib.Error{
			Message: lib.ErrInvalidIntegrity,
			Code:    0x106,
			Type:    lib.ValidationErrorType,
		}
	}
	if *o.AdditionalPassword == "" && *o.IntegrityProvider == integrity.TypeNameHMAC {
		return &lib.Error{
			Message: lib.ErrMissingPassword,
			Code:    0x107,
			Type:    lib.ValidationErrorType,
		}
	}
	if *o.TokenSavePath == "" && *o.TokenSaveType == TokenSaveTypeFile {
		return &lib.Error{
			Message: lib.ErrMissingKeyPath,
			Code:    0x108,
			Type:    lib.ValidationErrorType,
		}
	}

	return nil
}

func Encrypt(options Options) error {
	// compressing folder and getting data, compression
	data, compID, err := compressFolder(options)
	if err != nil {
		return &lib.Error{
			Message: fmt.Errorf("compress folder error; %w", err),
			Code:    0x111,
			Type:    lib.InternalErrorType,
		}
	}

	// create container and get master key and container salt
	masterKey, containerSalt, err := createContainer(options, data, compID)
	if err != nil {
		return &lib.Error{
			Message: fmt.Errorf("create container error; %w", err),
			Code:    0x112,
			Type:    lib.InternalErrorType,
		}
	}

	integrityProvider, err := createIntegrityProvider(options)
	if err != nil {
		return &lib.Error{
			Message: fmt.Errorf("create integrity provider error; %w", err),
			Code:    0x113,
			Type:    lib.InternalErrorType,
		}
	}

	additionalPassword, err := deriveAdditionalPassword(options, containerSalt)
	if err != nil {
		return &lib.Error{
			Message: fmt.Errorf("derive additional password error; %w", err),
			Code:    0x114,
			Type:    lib.InternalErrorType,
		}
	}

	if err = generateAndSaveTokens(options, additionalPassword, masterKey, integrityProvider); err != nil {
		return &lib.Error{
			Message: fmt.Errorf("generate and save tokens error; %w", err),
			Code:    0x115,
			Type:    lib.InternalErrorType,
		}
	}

	return nil
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
		return nil, 0, lib.ErrNoneCompressionUnimplemented
	default:
		return nil, 0, lib.ErrUnknownCompressionType
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
		return nil, lib.ErrEd25519Unimplemented
	default:
		return nil, lib.ErrUnknownIntegrityProvider
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
	TokenList map[int]string `json:"token_list"`
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
		TokenList: make(map[int]string, len(shares)),
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

		jsonTokenList.TokenList[int(share.ID)] = base64.StdEncoding.EncodeToString(shareToken)
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
