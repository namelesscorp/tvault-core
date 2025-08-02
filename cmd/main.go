package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/namelesscorp/tvault-core/container"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/token"
)

const (
	cliVersion = "v0.0.1"

	commandSeal    = "seal"
	commandUnseal  = "unseal"
	commandReseal  = "reseal"
	commandVersion = "version"
	commandInfo    = "info"

	subContainer         = "container"
	subCompression       = "compression"
	subIntegrityProvider = "integrity-provider"
	subShamir            = "shamir"
	subTokenWriter       = "token-writer"
	subTokenReader       = "token-reader"
	subLogWriter         = "log-writer"

	usageMessage = "usage: tvault-core <command> [subcommand] [options]\n" +
		"available commands: [%s | %s | %s | %s | %s]"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf(usageMessage, commandSeal, commandUnseal, commandReseal, commandVersion, commandInfo)
		return
	}

	switch os.Args[1] {
	case commandSeal:
		handleSeal(os.Args[2:])
	case commandUnseal:
		handleUnseal(os.Args[2:])
	case commandReseal:
		handleReseal(os.Args[2:])
	case commandVersion:
		fmt.Printf(
			"tvault-core:\n- cli = %s\n- container = v%d\n- token = v%d\n",
			cliVersion,
			container.Version,
			token.Version,
		)
	case commandInfo:
		fmt.Printf(
			"Trust Vault\n\n" +
				"links:\n" +
				"- github: https://github.com/namelesscorp/tvault-core\n" +
				"- website: https://tvault.app\n" +
				"- docs: https://docs.tvault.app\n\n" +
				"application info:\n" +
				"- encryption: AES-GCM with PBKDF2\n" +
				"- secret sharing: Shamir's Secret Sharing\n" +
				"- integrity provider: HMAC-SHA256\n" +
				"- compression type: ZIP\n\n" +
				"created by trust vault team (nameless)\n",
		)
	default:
		fmt.Printf(
			"unknown command: %s; use [%s | %s | %s | %s | %s]",
			os.Args[1],
			commandSeal,
			commandUnseal,
			commandReseal,
			commandVersion,
			commandInfo,
		)
	}
}

func findNextSubcommand(args []string, startIdx int) int {
	subcommands := map[string]bool{
		subContainer:         true,
		subCompression:       true,
		subIntegrityProvider: true,
		subShamir:            true,
		subTokenWriter:       true,
		subTokenReader:       true,
		subLogWriter:         true,
	}

	for i := startIdx; i < len(args); i++ {
		if args[i][0] == '-' {
			continue
		}

		if subcommands[args[i]] {
			return i
		}
	}

	return len(args)
}

func handleError(logWriter *lib.Writer, operation string, err error) {
	writer, closer, _ := lib.NewWriter(logWriter)
	if closer != nil {
		defer func(closer io.Closer) {
			_ = closer.Close()
		}(closer)
	}

	var errLib *lib.Error
	if ok := errors.As(err, &errLib); !ok {
		fmt.Printf("operation: %s; error: %v", operation, err)
		os.Exit(1)
		return
	}

	var message any
	switch *logWriter.Format {
	case lib.WriterFormatPlaintext:
		message = fmt.Sprintf(
			"operation: %s; code: %d; type: %b; message: %s",
			operation,
			errLib.Code,
			errLib.Type,
			errLib.Message,
		)
	case lib.WriterFormatJSON:
		message = errLib
	}

	if _, err = lib.WriteFormatted(writer, *logWriter.Format, message); err != nil {
		fmt.Printf("failed to write error message; %v", err)
	}

	os.Exit(1)
}
