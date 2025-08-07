package main

import (
	"fmt"
	"os"

	"github.com/namelesscorp/tvault-core/container"
	"github.com/namelesscorp/tvault-core/debug"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/token"
)

const (
	cliVersion = "v0.0.1"

	commandSeal      = "seal"
	commandUnseal    = "unseal"
	commandReseal    = "reseal"
	commandVersion   = "version"
	commandInfo      = "info"
	commandContainer = "container"

	subContainer         = "container"
	subInfo              = "info"
	subToken             = "token"
	subCompression       = "compression"
	subIntegrityProvider = "integrity-provider"
	subShamir            = "shamir"
	subInfoWriter        = "info-writer"
	subTokenWriter       = "token-writer"
	subTokenReader       = "token-reader"
	subLogWriter         = "log-writer"

	usageMessage = "usage: tvault-core <command> [subcommand] [options]\n" +
		"available commands: [%s | %s | %s | %s | %s]"
)

var (
	subcommands = map[string]bool{
		subContainer:         true,
		subToken:             true,
		subCompression:       true,
		subIntegrityProvider: true,
		subShamir:            true,
		subTokenWriter:       true,
		subTokenReader:       true,
		subLogWriter:         true,
		subInfoWriter:        true,
	}
)

func main() {
	defer func() {
		debug.Stop()

		if r := recover(); r != nil {
			fmt.Println("recovered from panic: ", r)
		}
	}()

	if len(os.Args) < 2 {
		fmt.Printf(usageMessage, commandSeal, commandUnseal, commandReseal, commandVersion, commandInfo)
		return
	}

	switch os.Args[1] {
	case commandSeal:
		if logWriter, err := handleSeal(os.Args[2:]); err != nil {
			lib.ErrorFormatted(logWriter, commandSeal, err)
			return
		}
	case commandUnseal:
		if logWriter, err := handleUnseal(os.Args[2:]); err != nil {
			lib.ErrorFormatted(logWriter, commandUnseal, err)
			return
		}

	case commandReseal:
		if logWriter, err := handleReseal(os.Args[2:]); err != nil {
			lib.ErrorFormatted(logWriter, commandReseal, err)
			return
		}
	case commandContainer:
		if logWriter, err := handleContainer(os.Args[2:]); err != nil {
			lib.ErrorFormatted(logWriter, commandContainer, err)
			return
		}
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
			"unknown command: %s; use [%s | %s | %s | %s | %s | %s]",
			os.Args[1],
			commandSeal,
			commandUnseal,
			commandReseal,
			commandContainer,
			commandVersion,
			commandInfo,
		)
	}
}

func findNextSubcommand(args []string, startIdx int) int {
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
