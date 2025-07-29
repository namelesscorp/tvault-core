package decrypt

import "github.com/namelesscorp/tvault-core/lib"

type Options struct {
	ContainerPath      *string
	FolderPath         *string
	AdditionalPassword *string

	TokenReaderType   *string
	TokenReaderPath   *string
	TokenReaderFlag   *string
	TokenReaderFormat *string

	LogWriterFormat *string
	LogWriterPath   *string
	LogWriterType   *string
}

func (o *Options) Validate() error {
	if err := o.validateSystem(); err != nil {
		return err
	}

	if err := o.validateTokenReader(); err != nil {
		return err
	}

	return o.validateLogWriter()
}

func (o *Options) validateSystem() error {
	switch {
	case *o.ContainerPath == "":
		return lib.ValidationErr(lib.ErrDecryptCodeContainerPathRequired, lib.ErrContainerPathRequired)
	case *o.FolderPath == "":
		return lib.ValidationErr(lib.ErrDecryptCodeFolderPathRequired, lib.ErrFolderPathRequired)
	default:
		return nil
	}
}

func (o *Options) validateTokenReader() error {
	if _, ok := lib.ReaderTypes[*o.TokenReaderType]; !ok {
		return lib.ValidationErr(lib.ErrDecryptCodeInvalidTokenReaderType, lib.ErrInvalidTokenReaderType)
	}

	switch *o.TokenReaderType {
	case lib.ReaderTypeFlag:
		if *o.TokenReaderFlag == "" {
			return lib.ValidationErr(lib.ErrDecryptCodeMissingTokenReaderFlag, lib.ErrMissingTokenReaderFlag)
		}
	case lib.ReaderTypeFile:
		if *o.TokenReaderPath == "" {
			return lib.ValidationErr(lib.ErrDecryptCodeMissingTokenReaderPath, lib.ErrMissingTokenReaderPath)
		}
	}

	if _, ok := lib.ReaderFormats[*o.TokenReaderFormat]; !ok {
		return lib.ValidationErr(lib.ErrDecryptCodeInvalidTokenReaderFmt, lib.ErrInvalidTokenReaderFormat)
	}

	return nil
}

func (o *Options) validateLogWriter() error {
	if _, ok := lib.WriterTypes[*o.LogWriterType]; !ok {
		return lib.ValidationErr(lib.ErrDecryptCodeInvalidLogWriterType, lib.ErrInvalidLogWriterType)
	}

	if *o.LogWriterType == lib.WriterTypeFile && *o.LogWriterPath == "" {
		return lib.ValidationErr(lib.ErrDecryptCodeMissingLogWriterPath, lib.ErrMissingLogWriterPath)
	}

	if _, ok := lib.WriterFormats[*o.LogWriterFormat]; !ok {
		return lib.ValidationErr(lib.ErrDecryptCodeInvalidLogWriterFormat, lib.ErrInvalidLogWriterFormat)
	}

	return nil
}
