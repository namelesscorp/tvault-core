package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/seal"
)

func handleSeal(args []string) {
	if len(args) < 1 {
		fmt.Printf("usage: tvault-core seal <subcommand> [options]\n")
		fmt.Printf("available subcommands: [%s | %s | %s | %s | %s | %s]\n",
			subContainer, subCompression, subIntegrityProvider,
			subShamir, subTokenWriter, subLogWriter)
		return
	}

	options := seal.Options{
		Container: &lib.Container{
			NewPath:     stringPtr(""),
			CurrentPath: stringPtr(""),
			FolderPath:  stringPtr(""),
			Passphrase:  stringPtr(""),
		},
		Compression: &lib.Compression{
			Type: stringPtr(compression.TypeNameZip),
		},
		IntegrityProvider: &lib.IntegrityProvider{
			Type:              stringPtr(integrity.TypeNameHMAC),
			CurrentPassphrase: stringPtr(""),
			NewPassphrase:     stringPtr(""),
		},
		Shamir: &lib.Shamir{
			Shares:    intPtr(5),
			Threshold: intPtr(3),
			IsEnabled: boolPtr(true),
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

	usedSubcommands := make(map[string]bool)
	for i := 0; i < len(args); {
		subcommand := args[i]

		nextSubcmdIdx := findNextSubcommand(args, i+1)

		subcommandArgs := args[i+1 : nextSubcmdIdx]

		usedSubcommands[subcommand] = true

		switch subcommand {
		case subContainer:
			processSealContainer(options.Container, subcommandArgs)
		case subCompression:
			processSealCompression(options.Compression, subcommandArgs)
		case subIntegrityProvider:
			processSealIntegrityProvider(options.IntegrityProvider, subcommandArgs)
		case subShamir:
			processSealShamir(options.Shamir, subcommandArgs)
		case subTokenWriter:
			processSealTokenWriter(options.TokenWriter, subcommandArgs)
		case subLogWriter:
			processSealLogWriter(options.LogWriter, subcommandArgs)
		default:
			fmt.Printf("unknown subcommand for seal: %s\n", subcommand)
			return
		}

		i = nextSubcmdIdx
	}

	if !usedSubcommands[subContainer] {
		fmt.Println("Error: 'container' subcommand is required for seal")
		return
	}

	if err := options.Validate(); err != nil {
		writer, closer, _ := lib.NewWriter(options.LogWriter)
		if closer != nil {
			defer func(closer io.Closer) {
				_ = closer.Close()
			}(closer)
		}
		handleError(nil, "validate seal options", *options.LogWriter.Format, writer, err)
		return
	}

	if err := seal.Seal(options); err != nil {
		writer, closer, _ := lib.NewWriter(options.LogWriter)
		if closer != nil {
			defer func(closer io.Closer) {
				_ = closer.Close()
			}(closer)
		}
		handleError(nil, commandSeal, *options.LogWriter.Format, writer, err)
	}
}

func processSealContainer(options *lib.Container, args []string) {
	flagSet := flag.NewFlagSet(subContainer, flag.ExitOnError)
	options.NewPath = flagSet.String("new-path", "", "new path to save container file")
	options.FolderPath = flagSet.String("folder-path", "", "path to folder for seal")
	options.Passphrase = flagSet.String("passphrase", "", "container passphrase")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("Failed to parse %s flags: %v\n", subContainer, err)
		os.Exit(1)
	}
}

func processSealCompression(options *lib.Compression, args []string) {
	flagSet := flag.NewFlagSet(subCompression, flag.ExitOnError)
	options.Type = flagSet.String("type", compression.TypeNameZip, "compression type [zip]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("Failed to parse %s flags: %v\n", subCompression, err)
		os.Exit(1)
	}
}

func processSealIntegrityProvider(options *lib.IntegrityProvider, args []string) {
	flagSet := flag.NewFlagSet(subIntegrityProvider, flag.ExitOnError)
	options.Type = flagSet.String("type", integrity.TypeNameHMAC, "type [none | hmac]")
	options.NewPassphrase = flagSet.String("new-passphrase", "", "new passphrase")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("Failed to parse %s flags: %v\n", subIntegrityProvider, err)
		os.Exit(1)
	}
}

func processSealShamir(options *lib.Shamir, args []string) {
	flagSet := flag.NewFlagSet(subShamir, flag.ExitOnError)
	options.Shares = flagSet.Int("shares", 5, "number of shares")
	options.Threshold = flagSet.Int("threshold", 3, "threshold of shares")
	options.IsEnabled = flagSet.Bool("is-enabled", true, "enable Shamir")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("Failed to parse %s flags: %v\n", subShamir, err)
		os.Exit(1)
	}
}

func processSealTokenWriter(options *lib.Writer, args []string) {
	flagSet := flag.NewFlagSet(subTokenWriter, flag.ExitOnError)
	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("Failed to parse %s flags: %v\n", subTokenWriter, err)
		os.Exit(1)
	}
}

func processSealLogWriter(options *lib.Writer, args []string) {
	flagSet := flag.NewFlagSet(subLogWriter, flag.ExitOnError)
	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf("Failed to parse %s flags: %v\n", subLogWriter, err)
		os.Exit(1)
	}
}
