package main

import (
	"flag"
	"fmt"

	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/unseal"
)

const usageUnsealTemplate = "usage: tvault-core unseal <subcommand> [options]\n" +
	"available subcommands: [%s | %s | %s | %s]"

func handleUnseal(args []string) (*lib.Writer, error) {
	var options = createDefaultUnsealOptions()
	if len(args) < 1 {
		return options.LogWriter, fmt.Errorf(
			usageUnsealTemplate,
			subContainer, subIntegrityProvider, subTokenReader, subLogWriter,
		)
	}

	var (
		usedSubcommands map[string]bool
		err             error
	)
	if usedSubcommands, err = parseUnsealSubcommands(args, &options); err != nil {
		return options.LogWriter, err
	}
	if !usedSubcommands[subContainer] {
		return options.LogWriter, fmt.Errorf(lib.ErrSubcommandRequired, subContainer, commandUnseal)
	}

	if err = options.Validate(); err != nil {
		return options.LogWriter, err
	}

	if err = unseal.Unseal(options); err != nil {
		return options.LogWriter, err
	}

	return options.LogWriter, nil
}

func createDefaultUnsealOptions() unseal.Options {
	return unseal.Options{
		Container: &lib.Container{
			NewPath:     lib.StringPtr(""),
			CurrentPath: lib.StringPtr(""),
			FolderPath:  lib.StringPtr(""),
			Passphrase:  lib.StringPtr(""),
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
		LogWriter: &lib.Writer{
			Type:   lib.StringPtr(lib.WriterTypeStdout),
			Path:   lib.StringPtr(""),
			Format: lib.StringPtr(lib.WriterFormatJSON),
		},
	}
}

func parseUnsealSubcommands(args []string, options *unseal.Options) (map[string]bool, error) {
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
			if err := processUnsealContainer(options.Container, subcommandArgs); err != nil {
				return nil, err
			}
		case subIntegrityProvider:
			if err := processUnsealIntegrityProvider(options.IntegrityProvider, subcommandArgs); err != nil {
				return nil, err
			}
		case subTokenReader:
			if err := processUnsealTokenReader(options.TokenReader, subcommandArgs); err != nil {
				return nil, err
			}
		case subLogWriter:
			if err := processUnsealLogWriter(options.LogWriter, subcommandArgs); err != nil {
				return nil, err
			}
		default:
			return usedSubcommands, fmt.Errorf(lib.ErrUnknownSubcommand, subcommand)
		}

		i = nextSubcommandIndex
	}

	return usedSubcommands, nil
}

func processUnsealContainer(options *lib.Container, args []string) error {
	var flagSet = flag.NewFlagSet(subContainer, flag.ExitOnError)

	options.CurrentPath = flagSet.String("current-path", "", "current path to container file (required); default: empty")
	options.FolderPath = flagSet.String("folder-path", "", "path to folder for unseal (required); default: empty")
	options.Passphrase = flagSet.String("passphrase", "", "passphrase to decrypt container file (required for seal token -type=none); default: empty")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subContainer, err)
	}

	return nil
}

func processUnsealIntegrityProvider(options *lib.IntegrityProvider, args []string) error {
	var flagSet = flag.NewFlagSet(subIntegrityProvider, flag.ExitOnError)

	options.CurrentPassphrase = flagSet.String("current-passphrase", "", "current passphrase (required for seal integrity-provider -type=hmac); default: empty")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subIntegrityProvider, err)
	}

	return nil
}

func processUnsealTokenReader(options *lib.Reader, args []string) error {
	var flagSet = flag.NewFlagSet(subTokenReader, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.ReaderTypeFlag, "type [file | stdin | flag]; default: flag")
	options.Path = flagSet.String("path", "", "path to file (required for -type=file); default: empty")
	options.Flag = flagSet.String("flag", "", "token from flag (required for -type=flag); default: empty")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]; default: json")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subTokenReader, err)
	}

	return nil
}

func processUnsealLogWriter(options *lib.Writer, args []string) error {
	var flagSet = flag.NewFlagSet(subLogWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]; default: stdout")
	options.Path = flagSet.String("path", "", "path to file (required for -type=file); default: empty")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]; default: json")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subLogWriter, err)
	}

	return nil
}
