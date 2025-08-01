package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/unseal"
)

func handleUnseal(args []string) {
	if len(args) < 1 {
		fmt.Printf("usage: tvault-core unseal <subcommand> [options]\n")
		fmt.Printf("available subcommands: [%s | %s | %s | %s]\n",
			subContainer, subIntegrityProvider, subTokenReader, subLogWriter)
		return
	}

	options := unseal.Options{
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
		LogWriter: &lib.Writer{
			Type:   stringPtr(lib.WriterTypeStdout),
			Path:   stringPtr(""),
			Format: stringPtr(lib.WriterFormatJSON),
		},
	}

	usedSubcommands := make(map[string]bool)
	for i := 0; i < len(args); {
		subcommand := args[i]

		nextSubcmdIdx := findNextSubcommand(args, i+1)

		subcommandArgs := args[i+1 : nextSubcmdIdx]

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
			fmt.Printf("unknown subcommand for unseal: %s\n", subcommand)
			return
		}

		i = nextSubcmdIdx
	}

	if !usedSubcommands[subContainer] {
		fmt.Println("Error: 'container' subcommand is required for unseal")
		return
	}

	if err := options.Validate(); err != nil {
		writer, closer, _ := lib.NewWriter(options.LogWriter)
		if closer != nil {
			defer func(closer io.Closer) {
				_ = closer.Close()
			}(closer)
		}
		handleError(nil, "validate unseal options", *options.LogWriter.Format, writer, err)
		return
	}

	if err := unseal.Unseal(options); err != nil {
		writer, closer, _ := lib.NewWriter(options.LogWriter)
		if closer != nil {
			defer func(closer io.Closer) {
				_ = closer.Close()
			}(closer)
		}
		handleError(nil, commandUnseal, *options.LogWriter.Format, writer, err)
	}
}

func processUnsealContainer(options *lib.Container, args []string) {
	flagSet := flag.NewFlagSet(subContainer, flag.ExitOnError)
	options.CurrentPath = flagSet.String("current-path", "", "current path to container file")
	options.FolderPath = flagSet.String("folder-path", "", "path to folder for unseal")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("Failed to parse %s flags: %v\n", subContainer, err)
		os.Exit(1)
	}
}

func processUnsealIntegrityProvider(options *lib.IntegrityProvider, args []string) {
	flagSet := flag.NewFlagSet(subIntegrityProvider, flag.ExitOnError)
	options.CurrentPassphrase = flagSet.String("current-passphrase", "", "current passphrase")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("Failed to parse %s flags: %v\n", subIntegrityProvider, err)
		os.Exit(1)
	}
}

func processUnsealTokenReader(options *lib.Reader, args []string) {
	flagSet := flag.NewFlagSet(subTokenReader, flag.ExitOnError)
	options.Type = flagSet.String("type", lib.ReaderTypeFlag, "type [file | stdin | flag]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Flag = flagSet.String("flag", "", "token from flag")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("Failed to parse %s flags: %v\n", subTokenReader, err)
		os.Exit(1)
	}
}

func processUnsealLogWriter(options *lib.Writer, args []string) {
	flagSet := flag.NewFlagSet(subLogWriter, flag.ExitOnError)
	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("Failed to parse %s flags: %v\n", subLogWriter, err)
		os.Exit(1)
	}
}
