package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/container"
	"github.com/namelesscorp/tvault-core/decrypt"
	"github.com/namelesscorp/tvault-core/encrypt"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/token"
)

const (
	cliVersion = "v0.0.1"

	commandEncrypt = "encrypt"
	commandDecrypt = "decrypt"
	commandVersion = "version"
	commandInfo    = "info"

	usageMessage = "usage: tvault-core <command> [options]\navailable commands: [%s | %s | %s | %s]"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf(usageMessage, commandEncrypt, commandDecrypt, commandVersion, commandInfo)
		return
	}

	switch os.Args[1] {
	case commandEncrypt:
		handleEncryptCommand()
	case commandDecrypt:
		handleDecryptCommand()
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
			"unknown command: %s; use [%s | %s | %s | %s]",
			os.Args[1],
			commandEncrypt,
			commandDecrypt,
			commandVersion,
			commandInfo,
		)
	}
}

func handleEncryptCommand() {
	encryptCmd := flag.NewFlagSet(commandEncrypt, flag.ExitOnError)
	encryptOptions := encrypt.Options{
		ContainerPath:      encryptCmd.String("container-path", "", "path to save container file"),
		FolderPath:         encryptCmd.String("folder-path", "", "path to folder for encryption"),
		Passphrase:         encryptCmd.String("passphrase", "", "passphrase for encrypt container"),
		AdditionalPassword: encryptCmd.String("additional-password", "", "additional password for integrity provider (required for -integrity-provider=hmac)"),

		CompressionType: encryptCmd.String("compression-type", compression.TypeNameZip, "type of compression [zip]"),

		IntegrityProvider: encryptCmd.String("integrity-provider", integrity.TypeNameHMAC, "type of integrity provider [none | hmac]"),

		Shares:          encryptCmd.Int("shares", 5, "number of shares (required for -is-shamir-enabled=true)"),
		Threshold:       encryptCmd.Int("threshold", 3, "threshold of shares (required for -is-shamir-enabled=true)"),
		IsShamirEnabled: encryptCmd.Bool("is-shamir-enabled", true, "enabling the Shamir algorithm [true | false]"),

		TokenWriterType:   encryptCmd.String("token-writer-type", lib.WriterTypeStdout, "type of token(s) writer [file | stdout]"),
		TokenWriterPath:   encryptCmd.String("token-writer-path", "", "path to write token(s) (required for -token-writer-type=file)"),
		TokenWriterFormat: encryptCmd.String("token-writer-format", lib.WriterFormatJSON, "format of writer output [plaintext | json]"),

		LogWriterType:   encryptCmd.String("log-writer-type", lib.WriterTypeStdout, "type of log(s) writer [file | stdout]"),
		LogWriterPath:   encryptCmd.String("log-writer-path", "", "path to write log(s) (required for -log-writer-type=file)"),
		LogWriterFormat: encryptCmd.String("log-writer-format", lib.WriterFormatJSON, "format of writer output [plaintext | json]"),
	}

	var err = parseAndValidateOptions(encryptCmd, os.Args[2:], encryptOptions.Validate)

	writer, closer, _ := lib.NewWriter(
		*encryptOptions.LogWriterType,
		*encryptOptions.LogWriterFormat,
		*encryptOptions.LogWriterPath,
	)
	if closer != nil {
		defer func() {
			_ = closer.Close()
		}()
	}

	if err != nil {
		handleError(encryptCmd, "validate encrypt options", *encryptOptions.LogWriterFormat, writer, err)
	}

	if err = encrypt.Encrypt(encryptOptions); err != nil {
		handleError(encryptCmd, "encryption", *encryptOptions.LogWriterFormat, writer, err)
	}
}

func handleDecryptCommand() {
	decryptCmd := flag.NewFlagSet(commandDecrypt, flag.ExitOnError)
	decryptOptions := decrypt.Options{
		ContainerPath:      decryptCmd.String("container-path", "", "path to container file"),
		FolderPath:         decryptCmd.String("folder-path", "", "path to folder for decryption"),
		AdditionalPassword: decryptCmd.String("additional-password", "", "additional password for integrity provider"),

		TokenReaderType:   decryptCmd.String("token-reader-type", lib.ReaderTypeFlag, "token(s) reader type [file | stdin | flag]"),
		TokenReaderPath:   decryptCmd.String("token-reader-path", "", "path to token(s) file (required for -token-reader-type=file)"),
		TokenReaderFlag:   decryptCmd.String("token-reader-flag", "", "token(s) for decrypt container by flag reader (required for -token-reader-type=flag)"),
		TokenReaderFormat: decryptCmd.String("token-reader-format", lib.WriterFormatJSON, "format of token(s) reader input [plaintext | json]"),

		LogWriterType:   decryptCmd.String("log-writer-type", lib.WriterTypeStdout, "type of log(s) writer [file | stdout]"),
		LogWriterPath:   decryptCmd.String("log-writer-path", "", "path to write log(s) (required for -log-writer-type=file)"),
		LogWriterFormat: decryptCmd.String("log-writer-format", lib.WriterFormatJSON, "format of writer output [plaintext | json]"),
	}

	var err = parseAndValidateOptions(decryptCmd, os.Args[2:], decryptOptions.Validate)

	writer, closer, _ := lib.NewWriter(
		*decryptOptions.LogWriterType,
		*decryptOptions.LogWriterFormat,
		*decryptOptions.LogWriterPath,
	)
	if closer != nil {
		defer func() {
			_ = closer.Close()
		}()
	}

	if err != nil {
		handleError(decryptCmd, "validate decrypt options", *decryptOptions.LogWriterFormat, writer, err)
	}

	if err = decrypt.Decrypt(decryptOptions); err != nil {
		handleError(decryptCmd, "decryption", *decryptOptions.LogWriterFormat, writer, err)
	}
}

func parseAndValidateOptions(flagSet *flag.FlagSet, args []string, validateFunc func() error) error {
	if err := flagSet.Parse(args); err != nil {
		return err
	}

	return validateFunc()
}

func handleError(flagSet *flag.FlagSet, operation, writerFormat string, writer io.Writer, err error) {
	flagSet.PrintDefaults()

	var errLib *lib.Error
	if ok := errors.As(err, &errLib); !ok {
		fmt.Printf("operation: %s; error: %v", operation, err)
		os.Exit(1)

		return
	}

	var message any
	switch writerFormat {
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

	if _, err = lib.WriteFormatted(writer, writerFormat, message); err != nil {
		fmt.Printf("failed to write error message; %v", err)
	}

	os.Exit(1)
}
