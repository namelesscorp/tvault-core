package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/unseal"
)

const usageUnsealTemplate = "usage: tvault-core unseal <subcommand> [options]\n" +
	"available subcommands: [%s | %s | %s | %s]"

func handleUnseal(args []string) {
	if len(args) < 1 {
		fmt.Printf(usageUnsealTemplate,
			subContainer, subIntegrityProvider, subTokenReader, subLogWriter,
		)
		return
	}

	var (
		options         = createDefaultUnsealOptions()
		usedSubcommands = parseUnsealSubcommands(args, &options)
	)
	if !usedSubcommands[subContainer] {
		fmt.Printf(lib.ErrSubcommandRequired, subContainer, commandUnseal)
		return
	}

	if err := options.Validate(); err != nil {
		handleError(options.LogWriter, commandUnseal, err)
		return
	}

	if err := unseal.Unseal(options); err != nil {
		handleError(options.LogWriter, commandUnseal, err)
		return
	}
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

func parseUnsealSubcommands(args []string, options *unseal.Options) map[string]bool {
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
			processUnsealContainer(options.Container, subcommandArgs)
		case subIntegrityProvider:
			processUnsealIntegrityProvider(options.IntegrityProvider, subcommandArgs)
		case subTokenReader:
			processUnsealTokenReader(options.TokenReader, subcommandArgs)
		case subLogWriter:
			processUnsealLogWriter(options.LogWriter, subcommandArgs)
		default:
			fmt.Printf(lib.ErrUnknownSubcommand, subcommand)
			return usedSubcommands
		}

		i = nextSubcommandIndex
	}

	return usedSubcommands
}

func processUnsealContainer(options *lib.Container, args []string) {
	var flagSet = flag.NewFlagSet(subContainer, flag.ExitOnError)

	options.CurrentPath = flagSet.String("current-path", "", "current path to container file")
	options.FolderPath = flagSet.String("folder-path", "", "path to folder for unseal")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subContainer, err)
		os.Exit(1)
	}
}

func processUnsealIntegrityProvider(options *lib.IntegrityProvider, args []string) {
	var flagSet = flag.NewFlagSet(subIntegrityProvider, flag.ExitOnError)

	options.CurrentPassphrase = flagSet.String("current-passphrase", "", "current passphrase")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subIntegrityProvider, err)
		os.Exit(1)
	}
}

func processUnsealTokenReader(options *lib.Reader, args []string) {
	var flagSet = flag.NewFlagSet(subTokenReader, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.ReaderTypeFlag, "type [file | stdin | flag]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Flag = flagSet.String("flag", "", "token from flag")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subTokenReader, err)
		os.Exit(1)
	}
}

func processUnsealLogWriter(options *lib.Writer, args []string) {
	var flagSet = flag.NewFlagSet(subLogWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subLogWriter, err)
		os.Exit(1)
	}
}
