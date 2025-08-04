package seal

import (
	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/token"
)

type Options struct {
	Container         *lib.Container
	Token             *lib.Token
	Compression       *lib.Compression
	IntegrityProvider *lib.IntegrityProvider
	Shamir            *lib.Shamir
	TokenWriter       *lib.Writer
	LogWriter         *lib.Writer
}

func (o *Options) Validate() error {
	if err := o.validateContainer(); err != nil {
		return err
	}

	if err := o.ValidateToken(); err != nil {
		return err
	}

	if err := o.validateCompression(); err != nil {
		return err
	}

	if err := o.validateIntegrity(); err != nil {
		return err
	}

	if err := o.validateShamir(); err != nil {
		return err
	}

	if err := o.validateTokenWriter(); err != nil {
		return err
	}

	return o.validateLogWriter()
}

func (o *Options) ValidateToken() error {
	if _, ok := token.Types[*o.Token.Type]; !ok {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrTokenTypeInvalid)
	}

	return nil
}

func (o *Options) validateContainer() error {
	switch {
	case *o.Container.NewPath == "":
		return lib.ValidationErr(lib.CategorySeal, lib.ErrContainerNewPathRequired)
	case *o.Container.FolderPath == "":
		return lib.ValidationErr(lib.CategorySeal, lib.ErrContainerFolderPathRequired)
	case *o.Container.Passphrase == "":
		return lib.ValidationErr(lib.CategorySeal, lib.ErrContainerPassphraseRequired)
	default:
		return nil
	}
}

func (o *Options) validateCompression() error {
	if _, ok := compression.Types[*o.Compression.Type]; !ok {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrCompressionTypeInvalid)
	}
	return nil
}

func (o *Options) validateIntegrity() error {
	if _, ok := integrity.Types[*o.IntegrityProvider.Type]; !ok {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrIntegrityProviderTypeInvalid)
	}

	if *o.Token.Type == token.TypeNameNone && *o.IntegrityProvider.Type != integrity.TypeNameNone {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrIntegrityProviderTypeNotNone)
	}

	if *o.IntegrityProvider.Type == integrity.TypeNameHMAC && *o.IntegrityProvider.NewPassphrase == "" {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrIntegrityProviderNewPassphraseRequired)
	}

	return nil
}

func (o *Options) validateShamir() error {
	if token.TypeNameShare == *o.Token.Type && !*o.Shamir.IsEnabled {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrShamirIsEnabledTrueRequired)
	}

	if !*o.Shamir.IsEnabled {
		return nil
	}

	if *o.Shamir.Shares == 0 {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrShamirSharesEqual0)
	}

	if *o.Shamir.Threshold == 0 {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrShamirThresholdEqual0)
	}

	if *o.Shamir.Shares < *o.Shamir.Threshold {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrShamirSharesLessThanThreshold)
	}

	if *o.Shamir.Shares < 2 {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrShamirSharesLessThan2)
	}

	if *o.Shamir.Threshold < 2 {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrShamirThresholdLessThan2)
	}

	if *o.Shamir.Shares > 255 {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrShamirSharesGreaterThan255)
	}

	if *o.Shamir.Threshold > 255 {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrShamirThresholdGreaterThan255)
	}

	return nil
}

func (o *Options) validateTokenWriter() error {
	if _, ok := lib.WriterTypes[*o.TokenWriter.Type]; !ok {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrTokenWriterTypeInvalid)
	}

	if *o.TokenWriter.Type == lib.WriterTypeFile && *o.TokenWriter.Path == "" {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrTokenWriterPathRequired)
	}

	if _, ok := lib.WriterFormats[*o.TokenWriter.Format]; !ok {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrTokenWriterFormatInvalid)
	}

	return nil
}

func (o *Options) validateLogWriter() error {
	if _, ok := lib.WriterTypes[*o.LogWriter.Type]; !ok {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrLogWriterTypeInvalid)
	}

	if *o.LogWriter.Type == lib.WriterTypeFile && *o.LogWriter.Path == "" {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrLogWriterPathRequired)
	}

	if _, ok := lib.WriterFormats[*o.LogWriter.Format]; !ok {
		return lib.ValidationErr(lib.CategorySeal, lib.ErrLogWriterFormatInvalid)
	}

	return nil
}
