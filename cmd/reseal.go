package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/reseal"
)

const usageResealTemplate = "usage: tvault-core reseal <subcommand> [options]\n" +
	"available subcommands: [%s | %s | %s | %s | %s]"

func handleReseal(args []string) {
	if len(args) < 1 {
		fmt.Printf(usageResealTemplate,
			subContainer, subIntegrityProvider, subTokenReader, subTokenWriter, subLogWriter,
		)
		return
	}

	var (
		options         = createDefaultResealOptions()
		usedSubcommands = parseResealSubcommands(args, &options)
	)
	if !usedSubcommands[subContainer] {
		fmt.Printf(lib.ErrSubcommandRequired, subContainer, commandReseal)
		return
	}

	if err := options.Validate(); err != nil {
		handleError(options.LogWriter, commandReseal, err)
		return
	}

	if err := reseal.Reseal(options); err != nil {
		handleError(options.LogWriter, commandReseal, err)
		return
	}
}

func createDefaultResealOptions() reseal.Options {
	return reseal.Options{
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

func parseResealSubcommands(args []string, options *reseal.Options) map[string]bool {
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
			processResealContainer(options.Container, subcommandArgs)
		case subIntegrityProvider:
			processResealIntegrityProvider(options.IntegrityProvider, subcommandArgs)
		case subTokenReader:
			processResealTokenReader(options.TokenReader, subcommandArgs)
		case subTokenWriter:
			processResealTokenWriter(options.TokenWriter, subcommandArgs)
		case subLogWriter:
			processResealLogWriter(options.LogWriter, subcommandArgs)
		default:
			fmt.Printf(lib.ErrUnknownSubcommand, subcommand)
			return usedSubcommands
		}

		i = nextSubcommandIndex
	}

	return usedSubcommands
}

func processResealContainer(options *lib.Container, args []string) {
	var flagSet = flag.NewFlagSet(subContainer, flag.ExitOnError)

	options.CurrentPath = flagSet.String("current-path", "", "current path to container file")
	options.NewPath = flagSet.String("new-path", "", "new path to save container file")
	options.FolderPath = flagSet.String("folder-path", "", "path to folder for reseal")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subContainer, err)
		os.Exit(1)
	}
}

func processResealIntegrityProvider(options *lib.IntegrityProvider, args []string) {
	var flagSet = flag.NewFlagSet(subIntegrityProvider, flag.ExitOnError)

	options.CurrentPassphrase = flagSet.String("current-passphrase", "", "current passphrase")
	options.NewPassphrase = flagSet.String("new-passphrase", "", "new passphrase")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subIntegrityProvider, err)
		os.Exit(1)
	}
}

func processResealTokenReader(options *lib.Reader, args []string) {
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

func processResealTokenWriter(options *lib.Writer, args []string) {
	var flagSet = flag.NewFlagSet(subTokenWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subTokenWriter, err)
		os.Exit(1)
	}
}

func processResealLogWriter(options *lib.Writer, args []string) {
	var flagSet = flag.NewFlagSet(subLogWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subLogWriter, err)
		os.Exit(1)
	}
}
