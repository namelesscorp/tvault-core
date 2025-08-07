package container

import (
	"github.com/namelesscorp/tvault-core/lib"
)

type Options struct {
	Path       *string
	InfoWriter *lib.Writer
	LogWriter  *lib.Writer
}

func (o *Options) Validate() error {
	if *o.Path == "" {
		return lib.ValidationErr(lib.CategoryContainer, lib.ErrInfoPathRequired)
	}

	if err := o.validateInfoWriter(); err != nil {
		return err
	}

	if err := o.validateLogWriter(); err != nil {
		return err
	}

	return nil
}

func (o *Options) validateInfoWriter() error {
	if _, ok := lib.WriterTypes[*o.InfoWriter.Type]; !ok {
		return lib.ValidationErr(lib.CategoryContainer, lib.ErrInfoWriterTypeInvalid)
	}

	if *o.InfoWriter.Type == lib.WriterTypeFile && *o.InfoWriter.Path == "" {
		return lib.ValidationErr(lib.CategoryContainer, lib.ErrInfoWriterPathRequired)
	}

	if _, ok := lib.WriterFormats[*o.InfoWriter.Format]; !ok {
		return lib.ValidationErr(lib.CategoryContainer, lib.ErrInfoWriterFormatInvalid)
	}

	return nil
}

func (o *Options) validateLogWriter() error {
	if _, ok := lib.WriterTypes[*o.LogWriter.Type]; !ok {
		return lib.ValidationErr(lib.CategoryContainer, lib.ErrInfoWriterTypeInvalid)
	}

	if *o.LogWriter.Type == lib.WriterTypeFile && *o.LogWriter.Path == "" {
		return lib.ValidationErr(lib.CategoryContainer, lib.ErrInfoWriterPathRequired)
	}

	if _, ok := lib.WriterFormats[*o.LogWriter.Format]; !ok {
		return lib.ValidationErr(lib.CategoryContainer, lib.ErrInfoWriterFormatInvalid)
	}

	return nil
}
