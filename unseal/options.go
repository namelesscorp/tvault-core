package unseal

import "github.com/namelesscorp/tvault-core/lib"

type Options struct {
	Container         *lib.Container
	IntegrityProvider *lib.IntegrityProvider
	TokenReader       *lib.Reader
	LogWriter         *lib.Writer
}

func (o *Options) Validate() error {
	if err := o.validateContainer(); err != nil {
		return err
	}

	if err := o.validateTokenReader(); err != nil {
		return err
	}

	return o.validateLogWriter()
}

func (o *Options) validateContainer() error {
	switch {
	case *o.Container.CurrentPath == "":
		return lib.ValidationErr(
			lib.CategoryUnseal,
			lib.ErrContainerCurrentPathRequired,
		)
	case *o.Container.FolderPath == "":
		return lib.ValidationErr(
			lib.CategoryUnseal,
			lib.ErrContainerFolderPathRequired,
		)
	default:
		return nil
	}
}

func (o *Options) validateTokenReader() error {
	if _, ok := lib.ReaderTypes[*o.TokenReader.Type]; !ok {
		return lib.ValidationErr(
			lib.CategoryUnseal,
			lib.ErrTokenReaderTypeInvalid,
		)
	}

	switch *o.TokenReader.Type {
	case lib.ReaderTypeFlag:
		if *o.TokenReader.Flag == "" {
			return lib.ValidationErr(
				lib.CategoryUnseal,
				lib.ErrTokenReaderFlagRequired,
			)
		}
	case lib.ReaderTypeFile:
		if *o.TokenReader.Path == "" {
			return lib.ValidationErr(
				lib.CategoryUnseal,
				lib.ErrTokenReaderPathRequired,
			)
		}
	}

	if _, ok := lib.ReaderFormats[*o.TokenReader.Format]; !ok {
		return lib.ValidationErr(
			lib.CategoryUnseal,
			lib.ErrTokenReaderFormatInvalid,
		)
	}

	return nil
}

func (o *Options) validateLogWriter() error {
	if _, ok := lib.WriterTypes[*o.LogWriter.Type]; !ok {
		return lib.ValidationErr(
			lib.CategoryUnseal,
			lib.ErrLogWriterTypeInvalid,
		)
	}

	if *o.LogWriter.Type == lib.WriterTypeFile && *o.LogWriter.Path == "" {
		return lib.ValidationErr(
			lib.CategoryUnseal,
			lib.ErrLogWriterPathRequired,
		)
	}

	if _, ok := lib.WriterFormats[*o.LogWriter.Format]; !ok {
		return lib.ValidationErr(
			lib.CategoryUnseal,
			lib.ErrLogWriterFormatInvalid,
		)
	}

	return nil
}
