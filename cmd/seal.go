package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/seal"
)

const usageSealTemplate = "usage: tvault-core seal <subcommand> [options]\n" +
	"available subcommands: [%s | %s | %s | %s | %s | %s]"

func handleSeal(args []string) {
	if len(args) < 1 {
		fmt.Printf(usageSealTemplate,
			subContainer, subCompression, subIntegrityProvider,
			subShamir, subTokenWriter, subLogWriter,
		)
		return
	}

	var (
		options         = createDefaultSealOptions()
		usedSubcommands = parseSealSubcommands(args, &options)
	)
	if !usedSubcommands[subContainer] {
		fmt.Printf(lib.ErrSubcommandRequired, subContainer, commandSeal)
		return
	}

	if err := options.Validate(); err != nil {
		handleError(options.LogWriter, commandSeal, err)
		return
	}

	if err := seal.Seal(options); err != nil {
		handleError(options.LogWriter, commandSeal, err)
		return
	}
}

func createDefaultSealOptions() seal.Options {
	return seal.Options{
		Container: &lib.Container{
			NewPath:     lib.StringPtr(""),
			CurrentPath: lib.StringPtr(""),
			FolderPath:  lib.StringPtr(""),
			Passphrase:  lib.StringPtr(""),
		},
		Compression: &lib.Compression{
			Type: lib.StringPtr(compression.TypeNameZip),
		},
		IntegrityProvider: &lib.IntegrityProvider{
			Type:              lib.StringPtr(integrity.TypeNameHMAC),
			CurrentPassphrase: lib.StringPtr(""),
			NewPassphrase:     lib.StringPtr(""),
		},
		Shamir: &lib.Shamir{
			Shares:    lib.IntPtr(5),
			Threshold: lib.IntPtr(3),
			IsEnabled: lib.BoolPtr(true),
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

func parseSealSubcommands(args []string, options *seal.Options) map[string]bool {
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
			fmt.Printf(lib.ErrUnknownSubcommand, subcommand)
			return usedSubcommands
		}

		i = nextSubcommandIndex
	}

	return usedSubcommands
}

func processSealContainer(options *lib.Container, args []string) {
	var flagSet = flag.NewFlagSet(subContainer, flag.ExitOnError)

	options.NewPath = flagSet.String("new-path", "", "new path to save container file")
	options.FolderPath = flagSet.String("folder-path", "", "path to folder for seal")
	options.Passphrase = flagSet.String("passphrase", "", "container passphrase")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subContainer, err)
		os.Exit(1)
	}
}

func processSealCompression(options *lib.Compression, args []string) {
	var flagSet = flag.NewFlagSet(subCompression, flag.ExitOnError)

	options.Type = flagSet.String("type", compression.TypeNameZip, "compression type [zip]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subCompression, err)
		os.Exit(1)
	}
}

func processSealIntegrityProvider(options *lib.IntegrityProvider, args []string) {
	var flagSet = flag.NewFlagSet(subIntegrityProvider, flag.ExitOnError)

	options.Type = flagSet.String("type", integrity.TypeNameHMAC, "type [none | hmac]")
	options.NewPassphrase = flagSet.String("new-passphrase", "", "new passphrase")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subIntegrityProvider, err)
		os.Exit(1)
	}
}

func processSealShamir(options *lib.Shamir, args []string) {
	var flagSet = flag.NewFlagSet(subShamir, flag.ExitOnError)

	options.Shares = flagSet.Int("shares", 5, "number of shares")
	options.Threshold = flagSet.Int("threshold", 3, "threshold of shares")
	options.IsEnabled = flagSet.Bool("is-enabled", true, "enable Shamir")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subShamir, err)
		os.Exit(1)
	}
}

func processSealTokenWriter(options *lib.Writer, args []string) {
	var flagSet = flag.NewFlagSet(subTokenWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subTokenWriter, err)
		os.Exit(1)
	}
}

func processSealLogWriter(options *lib.Writer, args []string) {
	var flagSet = flag.NewFlagSet(subLogWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		fmt.Printf(lib.ErrFailedParseFlags, subLogWriter, err)
		os.Exit(1)
	}
}
