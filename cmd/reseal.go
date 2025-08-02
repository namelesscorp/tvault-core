package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/reseal"
)

func handleReseal(args []string) {
	if len(args) < 1 {
		fmt.Printf("usage: tvault-core reseal <subcommand> [options]\n")
		fmt.Printf("available subcommands: [%s | %s | %s | %s | %s]\n",
			subContainer, subIntegrityProvider, subTokenReader, subTokenWriter, subLogWriter,
		)
		return
	}

	options := reseal.Options{
		Container: &lib.Container{
			NewPath:     stringPtr(""),
			CurrentPath: stringPtr(""),
			FolderPath:  stringPtr(""),
			Passphrase:  stringPtr(""),
		},
		IntegrityProvider: &lib.IntegrityProvider{
			Type:              stringPtr(""),
			CurrentPassphrase: stringPtr(""),
			NewPassphrase:     stringPtr(""),
		},
		TokenReader: &lib.Reader{
			Type:   stringPtr(lib.ReaderTypeFlag),
			Path:   stringPtr(""),
			Flag:   stringPtr(""),
			Format: stringPtr(lib.WriterFormatJSON),
		},
		TokenWriter: &lib.Writer{
			Type:   stringPtr(lib.WriterTypeStdout),
			Path:   stringPtr(""),
			Format: stringPtr(lib.WriterFormatJSON),
		},
		LogWriter: &lib.Writer{
			Type:   stringPtr(lib.WriterTypeStdout),
			Path:   stringPtr(""),
			Format: stringPtr(lib.WriterFormatJSON),
		},
	}

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
			fmt.Printf("unknown subcommand for reseal: '%s'\n", subcommand)
			return
		}

		i = nextSubcommandIndex
	}

	if !usedSubcommands[subContainer] {
		fmt.Println("error: 'container' subcommand is required for reseal")
		return
	}

	if err := options.Validate(); err != nil {
		writer, closer, _ := lib.NewWriter(options.LogWriter)
		if closer != nil {
			defer func(closer io.Closer) {
				_ = closer.Close()
			}(closer)
		}
		handleError(nil, "validate reseal options", *options.LogWriter.Format, writer, err)
		return
	}

	if err := reseal.Reseal(options); err != nil {
		writer, closer, _ := lib.NewWriter(options.LogWriter)
		if closer != nil {
			defer func(closer io.Closer) {
				_ = closer.Close()
			}(closer)
		}
		handleError(nil, commandReseal, *options.LogWriter.Format, writer, err)
	}
}

func processResealContainer(options *lib.Container, args []string) {
	var flagSet = flag.NewFlagSet(subContainer, flag.ExitOnError)

	options.CurrentPath = flagSet.String("current-path", "", "current path to container file")
	options.NewPath = flagSet.String("new-path", "", "new path to save container file")
	options.FolderPath = flagSet.String("folder-path", "", "path to folder for reseal")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("failed to parse '%s' flags; %v\n", subContainer, err)
		os.Exit(1)
	}
}

func processResealIntegrityProvider(options *lib.IntegrityProvider, args []string) {
	var flagSet = flag.NewFlagSet(subIntegrityProvider, flag.ExitOnError)

	options.CurrentPassphrase = flagSet.String("current-passphrase", "", "current passphrase")
	options.NewPassphrase = flagSet.String("new-passphrase", "", "new passphrase")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("failed to parse '%s' flags; %v\n", subIntegrityProvider, err)
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
		fmt.Printf("failed to parse '%s' flags; %v\n", subTokenReader, err)
		os.Exit(1)
	}
}

func processResealTokenWriter(options *lib.Writer, args []string) {
	var flagSet = flag.NewFlagSet(subTokenWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("failed to parse '%s' flags; %v\n", subTokenWriter, err)
		os.Exit(1)
	}
}

func processResealLogWriter(options *lib.Writer, args []string) {
	var flagSet = flag.NewFlagSet(subLogWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("failed to parse '%s' flags; %v\n", subLogWriter, err)
		os.Exit(1)
	}
}
