package reseal

import "github.com/namelesscorp/tvault-core/lib"

type Options struct {
	Container         *lib.Container
	IntegrityProvider *lib.IntegrityProvider
	TokenReader       *lib.Reader
	TokenWriter       *lib.Writer
	LogWriter         *lib.Writer
}

func (o *Options) Validate() error {
	if err := o.validateContainer(); err != nil {
		return err
	}

	if err := o.validateTokenReader(); err != nil {
		return err
	}

	if err := o.validateTokenWriter(); err != nil {
		return err
	}

	if err := o.validateLogWriter(); err != nil {
		return err
	}

	return nil
}

func (o *Options) validateContainer() error {
	switch {
	case *o.Container.CurrentPath == "":
		return lib.ValidationErr(lib.ErrCodeResealContainerCurrentPathRequired, lib.ErrContainerCurrentPathRequired)
	case *o.Container.FolderPath == "":
		return lib.ValidationErr(lib.ErrCodeResealContainerFolderPathRequired, lib.ErrContainerFolderPathRequired)
	default:
		return nil
	}
}

func (o *Options) validateTokenReader() error {
	if _, ok := lib.ReaderTypes[*o.TokenReader.Type]; !ok {
		return lib.ValidationErr(lib.ErrCodeResealTokenReaderTypeInvalid, lib.ErrTokenReaderTypeInvalid)
	}

	switch *o.TokenReader.Type {
	case lib.ReaderTypeFlag:
		if *o.TokenReader.Flag == "" {
			return lib.ValidationErr(lib.ErrCodeResealTokenReaderFlagRequired, lib.ErrTokenReaderFlagRequired)
		}
	case lib.ReaderTypeFile:
		if *o.TokenReader.Path == "" {
			return lib.ValidationErr(lib.ErrCodeResealTokenReaderPathRequired, lib.ErrTokenReaderPathRequired)
		}
	}

	if _, ok := lib.ReaderFormats[*o.TokenReader.Format]; !ok {
		return lib.ValidationErr(lib.ErrCodeResealTokenReaderFormatInvalid, lib.ErrTokenReaderFormatInvalid)
	}

	return nil
}

func (o *Options) validateTokenWriter() error {
	if _, ok := lib.WriterTypes[*o.TokenWriter.Type]; !ok {
		return lib.ValidationErr(lib.ErrCodeResealTokenWriterTypeInvalid, lib.ErrTokenWriterTypeInvalid)
	}

	if *o.TokenWriter.Type == lib.WriterTypeFile && *o.TokenWriter.Path == "" {
		return lib.ValidationErr(lib.ErrCodeResealTokenWriterPathRequired, lib.ErrTokenWriterPathRequired)
	}

	if _, ok := lib.WriterFormats[*o.TokenWriter.Format]; !ok {
		return lib.ValidationErr(lib.ErrCodeResealTokenWriterFormatInvalid, lib.ErrTokenWriterFormatInvalid)
	}

	return nil
}

func (o *Options) validateLogWriter() error {
	if _, ok := lib.WriterTypes[*o.LogWriter.Type]; !ok {
		return lib.ValidationErr(lib.ErrCodeResealLogWriterTypeInvalid, lib.ErrLogWriterTypeInvalid)
	}

	if *o.LogWriter.Type == lib.WriterTypeFile && *o.LogWriter.Path == "" {
		return lib.ValidationErr(lib.ErrCodeResealLogWriterPathRequired, lib.ErrLogWriterPathRequired)
	}

	if _, ok := lib.WriterFormats[*o.LogWriter.Format]; !ok {
		return lib.ValidationErr(lib.ErrCodeResealLogWriterFormatInvalid, lib.ErrLogWriterFormatInvalid)
	}

	return nil
}
