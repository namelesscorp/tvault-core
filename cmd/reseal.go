package main

import (
	"flag"
	"fmt"

	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/reseal"
)

const usageResealTemplate = "usage: tvault-core reseal <subcommand> [options]\n" +
	"available subcommands: [%s | %s | %s | %s | %s]"

func handleReseal(args []string) (*lib.Writer, error) {
	var options = createDefaultResealOptions()
	if len(args) < 1 {
		return options.LogWriter, fmt.Errorf(
			usageResealTemplate,
			subContainer, subIntegrityProvider, subTokenReader, subTokenWriter, subLogWriter,
		)
	}

	var (
		usedSubcommands map[string]bool
		err             error
	)
	if usedSubcommands, err = parseResealSubcommands(args, &options); err != nil {
		return options.LogWriter, err
	}

	if !usedSubcommands[subContainer] {
		return options.LogWriter, fmt.Errorf(lib.ErrSubcommandRequired, subContainer, commandReseal)
	}

	if err = options.Validate(); err != nil {
		return options.LogWriter, err
	}

	if err = reseal.Reseal(options); err != nil {
		return options.LogWriter, err
	}

	return options.LogWriter, nil
}

func createDefaultResealOptions() reseal.Options {
	return reseal.Options{
		Container: &lib.Container{
			NewPath:     lib.StringPtr(""),
			CurrentPath: lib.StringPtr(""),
			FolderPath:  lib.StringPtr(""),
			Passphrase:  lib.StringPtr(""),
			Comment:     lib.StringPtr(""),
			Tags:        lib.StringPtr(""),
		},
		IntegrityProvider: &lib.IntegrityProvider{
			Type:              lib.StringPtr(""),
			CurrentPassphrase: lib.StringPtr(""),
			NewPassphrase:     lib.StringPtr(""),
		},
		TokenReader: &lib.Reader{
			Type:   lib.StringPtr(lib.ReaderTypeFlag),
			Path:   lib.StringPtr(""),
			Flag:   lib.StringPtr(""),
			Format: lib.StringPtr(lib.WriterFormatJSON),
		},
		TokenWriter: &lib.Writer{
			Type:   lib.StringPtr(lib.WriterTypeStdout),
			Path:   lib.StringPtr(""),
			Format: lib.StringPtr(lib.WriterFormatJSON),
		},
		LogWriter: &lib.Writer{
			Type:   lib.StringPtr(lib.WriterTypeStdout),
			Path:   lib.StringPtr(""),
			Format: lib.StringPtr(lib.WriterFormatJSON),
		},
	}
}

func parseResealSubcommands(args []string, options *reseal.Options) (map[string]bool, error) {
	var usedSubcommands = make(map[string]bool)
	for i := 0; i < len(args); {
		var (
			subcommand          = args[i]
			nextSubcommandIndex = findNextSubcommand(args, i+1)
			subcommandArgs      = args[i+1 : nextSubcommandIndex]
		)

		usedSubcommands[subcommand] = true

		switch subcommand {
		case subContainer:
			if err := processResealContainer(options.Container, subcommandArgs); err != nil {
				return nil, err
			}
		case subIntegrityProvider:
			if err := processResealIntegrityProvider(options.IntegrityProvider, subcommandArgs); err != nil {
				return nil, err
			}
		case subTokenReader:
			if err := processResealTokenReader(options.TokenReader, subcommandArgs); err != nil {
				return nil, err
			}
		case subTokenWriter:
			if err := processResealTokenWriter(options.TokenWriter, subcommandArgs); err != nil {
				return nil, err
			}
		case subLogWriter:
			if err := processResealLogWriter(options.LogWriter, subcommandArgs); err != nil {
				return nil, err
			}
		default:
			return usedSubcommands, fmt.Errorf(lib.ErrUnknownSubcommand, subcommand)
		}

		i = nextSubcommandIndex
	}

	return usedSubcommands, nil
}

func processResealContainer(options *lib.Container, args []string) error {
	var flagSet = flag.NewFlagSet(subContainer, flag.ExitOnError)

	options.CurrentPath = flagSet.String("current-path", "", "current path to container file")
	options.NewPath = flagSet.String("new-path", "", "new path to save container file")
	options.FolderPath = flagSet.String("folder-path", "", "path to folder for reseal")
	options.Passphrase = flagSet.String("passphrase", "", "passphrase to reseal container file")
	options.Comment = flagSet.String("comment", "", "container comment")
	options.Tags = flagSet.String("tags", "", "container tags")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subContainer, err)
	}

	return nil
}

func processResealIntegrityProvider(options *lib.IntegrityProvider, args []string) error {
	var flagSet = flag.NewFlagSet(subIntegrityProvider, flag.ExitOnError)

	options.CurrentPassphrase = flagSet.String("current-passphrase", "", "current passphrase")
	options.NewPassphrase = flagSet.String("new-passphrase", "", "new passphrase")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subIntegrityProvider, err)
	}

	return nil
}

func processResealTokenReader(options *lib.Reader, args []string) error {
	var flagSet = flag.NewFlagSet(subTokenReader, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.ReaderTypeFlag, "type [file | stdin | flag]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Flag = flagSet.String("flag", "", "token from flag")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subTokenReader, err)
	}

	return nil
}

func processResealTokenWriter(options *lib.Writer, args []string) error {
	var flagSet = flag.NewFlagSet(subTokenWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subTokenWriter, err)
	}

	return nil
}

func processResealLogWriter(options *lib.Writer, args []string) error {
	var flagSet = flag.NewFlagSet(subLogWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subLogWriter, err)
	}

	return nil
}
