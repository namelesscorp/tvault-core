package main

import (
	"flag"
	"fmt"

	"github.com/namelesscorp/tvault-core/container"
	"github.com/namelesscorp/tvault-core/lib"
)

const usageContainerTemplate = "usage: tvault-core container <subcommand> [options]\n" +
	"available subcommands: [%s | %s | %s]"

func handleContainer(args []string) (*lib.Writer, error) {
	var options = createDefaultContainerOptions()
	if len(args) < 1 {
		return options.LogWriter, fmt.Errorf(usageContainerTemplate, subInfo, subInfoWriter, subLogWriter)
	}

	var (
		usedSubcommands map[string]bool
		err             error
	)
	if usedSubcommands, err = parseContainerSubcommands(args, &options); err != nil {
		return options.LogWriter, err
	}

	if !usedSubcommands[subInfo] {
		return options.LogWriter, fmt.Errorf(lib.ErrSubcommandRequired, subInfo, commandContainer)
	}

	if err = options.Validate(); err != nil {
		return options.LogWriter, err
	}

	if err = container.Info(options); err != nil {
		return options.LogWriter, err
	}

	return options.LogWriter, nil
}

func createDefaultContainerOptions() container.Options {
	return container.Options{
		Path: lib.StringPtr(""),
		InfoWriter: &lib.Writer{
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

func parseContainerSubcommands(args []string, options *container.Options) (map[string]bool, error) {
	var usedSubcommands = make(map[string]bool)
	for i := 0; i < len(args); {
		var (
			subcommand          = args[i]
			nextSubcommandIndex = findNextSubcommand(args, i+1)
			subcommandArgs      = args[i+1 : nextSubcommandIndex]
		)

		usedSubcommands[subcommand] = true

		switch subcommand {
		case subInfo:
			if err := processContainerInfo(options, subcommandArgs); err != nil {
				return nil, err
			}
		case subInfoWriter:
			if err := processContainerInfoWriter(options.InfoWriter, subcommandArgs); err != nil {
				return nil, err
			}
		case subLogWriter:
			if err := processContainerLogWriter(options.LogWriter, subcommandArgs); err != nil {
				return nil, err
			}
		default:
			return usedSubcommands, fmt.Errorf(lib.ErrUnknownSubcommand, subcommand)
		}

		i = nextSubcommandIndex
	}

	return usedSubcommands, nil
}

func processContainerInfo(options *container.Options, args []string) error {
	var flagSet = flag.NewFlagSet(subInfo, flag.ExitOnError)

	options.Path = flagSet.String("path", "", "path to container (required flag)")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subInfo, err)
	}

	return nil
}

func processContainerInfoWriter(options *lib.Writer, args []string) error {
	var flagSet = flag.NewFlagSet(subInfoWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file (required for -type=file)")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subInfoWriter, err)
	}

	return nil
}

func processContainerLogWriter(options *lib.Writer, args []string) error {
	var flagSet = flag.NewFlagSet(subLogWriter, flag.ExitOnError)

	options.Type = flagSet.String("type", lib.WriterTypeStdout, "type [file | stdout]")
	options.Path = flagSet.String("path", "", "path to file (required for -type=file)")
	options.Format = flagSet.String("format", lib.WriterFormatJSON, "format [plaintext | json]")

	if err := flagSet.Parse(args); err != nil {
		return fmt.Errorf(lib.ErrFailedParseFlags, subLogWriter, err)
	}

	return nil
}
