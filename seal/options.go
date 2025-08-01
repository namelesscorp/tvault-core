package seal

import (
	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/lib"
)

type Options struct {
	Container         *lib.Container
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

func (o *Options) validateContainer() error {
	switch {
	case *o.Container.NewPath == "":
		return lib.ValidationErr(lib.ErrCodeSealContainerNewPathRequired, lib.ErrContainerNewPathRequired)
	case *o.Container.FolderPath == "":
		return lib.ValidationErr(lib.ErrCodeSealContainerFolderPathRequired, lib.ErrContainerFolderPathRequired)
	case *o.Container.Passphrase == "":
		return lib.ValidationErr(lib.ErrCodeSealContainerPassphraseRequired, lib.ErrContainerPassphraseRequired)
	default:
		return nil
	}
}

func (o *Options) validateCompression() error {
	if _, ok := compression.Types[*o.Compression.Type]; !ok {
		return lib.ValidationErr(lib.ErrCodeSealCompressionTypeInvalid, lib.ErrCompressionTypeInvalid)
	}
	return nil
}

func (o *Options) validateIntegrity() error {
	if _, ok := integrity.Types[*o.IntegrityProvider.Type]; !ok {
		return lib.ValidationErr(lib.ErrCodeSealIntegrityProviderTypeInvalid, lib.ErrIntegrityProviderTypeInvalid)
	}

	if *o.IntegrityProvider.Type == integrity.TypeNameHMAC && *o.IntegrityProvider.NewPassphrase == "" {
		return lib.ValidationErr(
			lib.ErrCodeSealIntegrityProviderNewPassphraseRequired,
			lib.ErrIntegrityProviderNewPassphraseRequired,
		)
	}

	return nil
}

func (o *Options) validateShamir() error {
	if !*o.Shamir.IsEnabled {
		return nil
	}

	if *o.Shamir.Shares == 0 {
		return lib.ValidationErr(lib.ErrCodeSealShamirSharesEqualZero, lib.ErrShamirSharesEqual0)
	}

	if *o.Shamir.Threshold == 0 {
		return lib.ValidationErr(lib.ErrCodeSealShamirThresholdEqualZero, lib.ErrShamirThresholdEqual0)
	}

	if *o.Shamir.Shares < *o.Shamir.Threshold {
		return lib.ValidationErr(lib.ErrCodeSealShamirSharesLessThanThreshold, lib.ErrShamirSharesLessThanThreshold)
	}

	if *o.Shamir.Shares < 2 {
		return lib.ValidationErr(lib.ErrCodeSealShamirSharesLessThanTwo, lib.ErrShamirSharesLessThan2)
	}

	if *o.Shamir.Threshold < 2 {
		return lib.ValidationErr(lib.ErrCodeSealShamirThresholdLessThanTwo, lib.ErrShamirThresholdLessThan2)
	}

	if *o.Shamir.Shares > 255 {
		return lib.ValidationErr(lib.ErrCodeSealShamirSharesGreaterThan255, lib.ErrShamirSharesGreaterThan255)
	}

	if *o.Shamir.Threshold > 255 {
		return lib.ValidationErr(lib.ErrCodeSealShamirThresholdGreaterThan255, lib.ErrShamirThresholdGreaterThan255)
	}

	return nil
}

func (o *Options) validateTokenWriter() error {
	if _, ok := lib.WriterTypes[*o.TokenWriter.Type]; !ok {
		return lib.ValidationErr(lib.ErrCodeSealTokenWriterTypeInvalid, lib.ErrTokenWriterTypeInvalid)
	}

	if *o.TokenWriter.Type == lib.WriterTypeFile && *o.TokenWriter.Path == "" {
		return lib.ValidationErr(lib.ErrCodeSealTokenWriterPathRequired, lib.ErrTokenWriterPathRequired)
	}

	if _, ok := lib.WriterFormats[*o.TokenWriter.Format]; !ok {
		return lib.ValidationErr(lib.ErrCodeSealTokenWriterFormatInvalid, lib.ErrTokenWriterFormatInvalid)
	}

	return nil
}

func (o *Options) validateLogWriter() error {
	if _, ok := lib.WriterTypes[*o.LogWriter.Type]; !ok {
		return lib.ValidationErr(lib.ErrCodeSealLogWriterTypeInvalid, lib.ErrLogWriterTypeInvalid)
	}

	if *o.LogWriter.Type == lib.WriterTypeFile && *o.LogWriter.Path == "" {
		return lib.ValidationErr(lib.ErrCodeSealLogWriterPathRequired, lib.ErrLogWriterPathRequired)
	}

	if _, ok := lib.WriterFormats[*o.LogWriter.Format]; !ok {
		return lib.ValidationErr(lib.ErrCodeSealLogWriterFormatInvalid, lib.ErrLogWriterFormatInvalid)
	}

	return nil
}
