package encrypt

import (
	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/lib"
)

type Options struct {
	// system
	ContainerPath      *string
	FolderPath         *string
	Passphrase         *string
	AdditionalPassword *string

	// compression
	CompressionType *string

	// integrity
	IntegrityProvider *string

	// shamir
	Shares          *int
	Threshold       *int
	IsShamirEnabled *bool

	// token
	TokenWriterType   *string
	TokenWriterPath   *string
	TokenWriterFormat *string

	// log
	LogWriterFormat *string
	LogWriterPath   *string
	LogWriterType   *string
}

func (o *Options) Validate() error {
	if err := o.validateSystem(); err != nil {
		return err
	}

	if err := o.validateCompression(); err != nil {
		return err
	}

	if err := o.validateIntegrity(); err != nil {
		return err
	}

	if err := o.validateTokenWriter(); err != nil {
		return err
	}

	return o.validateLogWriter()
}

func (o *Options) validateSystem() error {
	switch {
	case *o.ContainerPath == "":
		return lib.ValidationErr(lib.ErrEncryptCodeContainerPathRequired, lib.ErrContainerPathRequired)
	case *o.FolderPath == "":
		return lib.ValidationErr(lib.ErrEncryptCodeFolderPathRequired, lib.ErrFolderPathRequired)
	case *o.Passphrase == "":
		return lib.ValidationErr(lib.ErrEncryptCodePassphraseRequired, lib.ErrPassphraseRequired)
	default:
		return nil
	}
}

func (o *Options) validateCompression() error {
	if _, ok := compression.Types[*o.CompressionType]; !ok {
		return lib.ValidationErr(lib.ErrEncryptCodeInvalidCompression, lib.ErrInvalidCompression)
	}
	return nil
}

func (o *Options) validateIntegrity() error {
	if _, ok := integrity.Types[*o.IntegrityProvider]; !ok {
		return lib.ValidationErr(lib.ErrEncryptCodeInvalidIntegrityProvider, lib.ErrInvalidIntegrity)
	}

	if *o.IntegrityProvider == integrity.TypeNameHMAC && *o.AdditionalPassword == "" {
		return lib.ValidationErr(lib.ErrEncryptCodeMissingAdditionalPassword, lib.ErrMissingPassword)
	}

	return nil
}

func (o *Options) validateTokenWriter() error {
	if _, ok := lib.WriterTypes[*o.TokenWriterType]; !ok {
		return lib.ValidationErr(lib.ErrEncryptCodeInvalidTokenWriterType, lib.ErrInvalidTokenWriterType)
	}

	if *o.TokenWriterType == lib.WriterTypeFile && *o.TokenWriterPath == "" {
		return lib.ValidationErr(lib.ErrEncryptCodeMissingTokenWriterPath, lib.ErrMissingTokenWriterPath)
	}

	if _, ok := lib.WriterFormats[*o.TokenWriterFormat]; !ok {
		return lib.ValidationErr(lib.ErrEncryptCodeInvalidTokenWriterFormat, lib.ErrInvalidTokenWriterFormat)
	}

	return nil
}

func (o *Options) validateLogWriter() error {
	if _, ok := lib.WriterTypes[*o.LogWriterType]; !ok {
		return lib.ValidationErr(lib.ErrEncryptCodeInvalidLogWriterType, lib.ErrInvalidLogWriterType)
	}

	if *o.LogWriterType == lib.WriterTypeFile && *o.LogWriterPath == "" {
		return lib.ValidationErr(lib.ErrEncryptCodeMissingLogWriterPath, lib.ErrMissingLogWriterPath)
	}

	if _, ok := lib.WriterFormats[*o.LogWriterFormat]; !ok {
		return lib.ValidationErr(lib.ErrEncryptCodeInvalidLogWriterFormat, lib.ErrInvalidLogWriterFormat)
	}

	return nil
}
