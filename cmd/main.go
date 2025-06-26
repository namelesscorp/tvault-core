package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/container"
	"github.com/namelesscorp/tvault-core/decrypt"
	"github.com/namelesscorp/tvault-core/encrypt"
	"github.com/namelesscorp/tvault-core/integrity"
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
		log.Printf(usageMessage, commandEncrypt, commandDecrypt, commandVersion, commandInfo)
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
				"created by trust vault team (nameless corp)\n",
		)
	default:
		log.Printf("unknown command: %s; use [%s | %s]", os.Args[1], commandEncrypt, commandDecrypt)
	}
}

func handleEncryptCommand() {
	encryptCmd := flag.NewFlagSet(commandEncrypt, flag.ExitOnError)
	encryptOptions := encrypt.Options{
		ContainerPath:      encryptCmd.String("container-path", "", "path to save container file"),
		FolderPath:         encryptCmd.String("folder-path", "", "path to folder for encryption"),
		CompressionType:    encryptCmd.String("compression-type", compression.TypeNameZip, "type of compression [zip]"),
		Passphrase:         encryptCmd.String("passphrase", "", "passphrase for encrypt container"),
		TokenSaveType:      encryptCmd.String("token-save-type", encrypt.TokenSaveTypeStdout, "type of token(s) save [file | stdout]"),
		TokenSavePath:      encryptCmd.String("token-save-path", "", "path to save token(s) (required for -token-save-type=file)"),
		IsShamirEnabled:    encryptCmd.Bool("is-shamir-enabled", true, "enabling the Shamir algorithm [true | false]"),
		NumberOfShares:     encryptCmd.Int("number-of-shares", 5, "number of shares (required for -is-shamir-enabled=true)"),
		Threshold:          encryptCmd.Int("threshold", 3, "threshold of shares (required for -is-shamir-enabled=true)"),
		IntegrityProvider:  encryptCmd.String("integrity-provider", integrity.TypeNameHMAC, "type of integrity provider [none | hmac]"),
		AdditionalPassword: encryptCmd.String("additional-password", "", "additional password for integrity provider (required for -integrity-provider=hmac)"),
	}

	if err := parseAndValidateOptions(encryptCmd, os.Args[2:], encryptOptions.Validate); err != nil {
		handleError(encryptCmd, "validate encrypt options", err)
	}

	if err := encrypt.Encrypt(encryptOptions); err != nil {
		handleError(encryptCmd, "encryption", err)
	}
}

func handleDecryptCommand() {
	decryptCmd := flag.NewFlagSet(commandDecrypt, flag.ExitOnError)
	decryptOptions := decrypt.Options{
		ContainerPath:      decryptCmd.String("container-path", "", "path to container file"),
		FolderPath:         decryptCmd.String("folder-path", "", "path to folder for decryption"),
		Token:              decryptCmd.String("token", "", "token(s) for decrypt container"),
		AdditionalPassword: decryptCmd.String("additional-password", "", "additional password for integrity provider"),
	}

	if err := parseAndValidateOptions(decryptCmd, os.Args[2:], decryptOptions.Validate); err != nil {
		handleError(decryptCmd, "validate decrypt options", err)
	}

	if err := decrypt.Decrypt(decryptOptions); err != nil {
		handleError(decryptCmd, "decryption", err)
	}
}

func parseAndValidateOptions(flagSet *flag.FlagSet, args []string, validateFunc func() error) error {
	if err := flagSet.Parse(args); err != nil {
		return err
	}
	return validateFunc()
}

func handleError(flagSet *flag.FlagSet, operation string, err error) {
	flagSet.PrintDefaults()
	log.Fatalf("%s error: %v", operation, err)
}
