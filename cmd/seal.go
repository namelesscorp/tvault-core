package main

import (
	"flag"
	"fmt"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/seal"
	"github.com/namelesscorp/tvault-core/token"
)

const usageSealTemplate = "usage: tvault-core seal <subcommand> [options]\n" +
	"available subcommands: [%s | %s | %s | %s | %s | %s | %s]"

func handleSeal(args []string) (*lib.Writer, error) {
	var options = createDefaultSealOptions()
	if len(args) < 1 {
		return options.LogWriter, fmt.Errorf(
			usageSealTemplate,
			subContainer, subToken, subCompression, subIntegrityProvider,
			subShamir, subTokenWriter, subLogWriter,
		)
	}

	var (
		usedSubcommands map[string]bool
		err             error
	)
	if usedSubcommands, err = parseSealSubcommands(args, &options); err != nil {
		return options.LogWriter, err
	}

	if !usedSubcommands[subContainer] {
		return options.LogWriter, fmt.Errorf(lib.ErrSubcommandRequired, subContainer, commandSeal)
	}

	if err = options.Validate(); err != nil {
		return options.LogWriter, err
	}

	if err = seal.Seal(options); err != nil {
		return options.LogWriter, err
	}

	return options.LogWriter, nil
}

func createDefaultSealOptions() seal.Options {
	return seal.Options{
		Container: &lib.Container{
			NewPath:     lib.StringPtr(""),
			CurrentPath: lib.StringPtr(""),
			FolderPath:  lib.StringPtr(""),
			Passphrase:  lib.StringPtr(""),
		},
		Token: &lib.Token{
			Type: lib.StringPtr(token.TypeNameShare),
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

func parseSealSubcommands(args []string, options *seal.Options) (map[string]bool, error) {
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
			if err := processSealContainer(options.Container, subcommandArgs); err != nil {
				return nil, err
			}
		case subToken:
			if err := processSealToken(options.Token, subcommandArgs); err != nil {
				return nil, err
			}
		case subCompression:
			if err := processSealCompression(options.Compression, subcommandArgs); err != nil {
				return nil, err
			}
		case subIntegrityProvider:
			if err := processSealIntegrityProvider(options.IntegrityProvider, subcommandArgs); err != nil {
				return nil, err
			}
		case subShamir:
			if err := processSealShamir(options.Shamir, subcommandArgs); err != nil {
				return nil, err
			}
		case subTokenWriter:
			if err := processSealTokenWriter(options.TokenWriter, subcommandArgs); err != nil {
				return nil, err
			}
		case subLogWriter:
			if err := processSealLogWriter(options.LogWriter, subcommandArgs); err != nil {
				return nil, err
			}
		default:
			return usedSubcommands, fmt.Errorf(lib.ErrUnknownSubcommand, subcommand)
		}

		i = nextSubcommandIndex
	}

	return usedSubcommands, nil
}

func processSealContainer(options *lib.Container, args []string) error {
	var flagSet = flag.NewFlagSet(subContainer, flag.ExitOnError)

	options.NewPath = flagSet.String("new-path", "", "new path to save container file")
	options.FolderPath = flagSet.String("folder-path", "", "path to folder for seal")
	options.Passphrase = flagSet.String("passphrase", "", "container passphrase")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subContainer, err)
	}

	return nil
}

func processSealToken(options *lib.Token, args []string) error {
	var flagSet = flag.NewFlagSet(subToken, flag.ExitOnError)

	options.Type = flagSet.String("type", token.TypeNameShare, "type [none | share | master]")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subToken, err)
	}

	return nil
}

func processSealCompression(options *lib.Compression, args []string) error {
	var flagSet = flag.NewFlagSet(subCompression, flag.ExitOnError)

	options.Type = flagSet.String("type", compression.TypeNameZip, "compression type [zip]")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subCompression, err)
	}

	return nil
}

func processSealIntegrityProvider(options *lib.IntegrityProvider, args []string) error {
	var flagSet = flag.NewFlagSet(subIntegrityProvider, flag.ExitOnError)

	options.Type = flagSet.String("type", integrity.TypeNameHMAC, "type [none | hmac]")
	options.NewPassphrase = flagSet.String("new-passphrase", "", "new passphrase")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subIntegrityProvider, err)
	}

	return nil
}

func processSealShamir(options *lib.Shamir, args []string) error {
	var flagSet = flag.NewFlagSet(subShamir, flag.ExitOnError)

	options.Shares = flagSet.Int("shares", 5, "number of shares")
	options.Threshold = flagSet.Int("threshold", 3, "threshold of shares")
	options.IsEnabled = flagSet.Bool("is-enabled", true, "enable Shamir")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subShamir, err)
	}

	return nil
}

func processSealTokenWriter(options *lib.Writer, args []string) error {
	var flagSet = flag.NewFlagSet(subTokenWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subTokenWriter, err)
	}

	return nil
}

func processSealLogWriter(options *lib.Writer, args []string) error {
	var flagSet = flag.NewFlagSet(subLogWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subLogWriter, err)
	}

	return nil
}
