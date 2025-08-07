package container

import (
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/lib"
	"github.com/namelesscorp/tvault-core/token"
)

const containerInformationMessage = "[container information]\nName: %s\nVersion: %d\nCreated at: %s\nUpdated at: %s\n" +
	"Comment: %s\nTags: %s\nToken type: %s\nProvider type: %s\nCompression type: %s\nShares: %d\nThreshold: %d\n"

type Information struct {
	Name                  string   `json:"name"`
	Version               uint8    `json:"version"`
	CreatedAt             string   `json:"created_at"`
	UpdatedAt             string   `json:"updated_at"`
	Comment               string   `json:"comment"`
	Tags                  []string `json:"tags"`
	TokenType             string   `json:"token_type"`
	IntegrityProviderType string   `json:"integrity_provider_type"`
	CompressionType       string   `json:"compression_type"`
	Shares                uint8    `json:"shares"`
	Threshold             uint8    `json:"threshold"`
}

func Info(opts Options) error {
	cont := NewContainer(
		*opts.Path,
		nil,
		Metadata{Tags: make([]string, 0)},
		Header{},
	)
	if err := cont.Read(); err != nil {
		return lib.IOErr(
			lib.CategoryContainer,
			lib.ErrCodeUnsealOpenContainerError,
			lib.ErrMessageUnsealOpenContainerError,
			"",
			err,
		)
	}

	writer, closer, err := lib.NewWriter(opts.InfoWriter)
	if err != nil {
		return err
	}

	if closer != nil {
		defer func(closer io.Closer) {
			_ = closer.Close()
		}(closer)
	}

	var (
		containerName = path.Base(*opts.Path)
		pathList      = strings.Split(containerName, ".")
	)
	if len(pathList) == 2 {
		containerName = pathList[0]
	}

	var msg any
	switch *opts.InfoWriter.Format {
	case lib.WriterFormatPlaintext:
		msg = fmt.Sprintf(
			containerInformationMessage,
			containerName,
			cont.GetHeader().Version,
			cont.GetMetadata().CreatedAt.Format(time.DateTime),
			cont.GetMetadata().UpdatedAt.Format(time.DateTime),
			cont.GetMetadata().Comment,
			strings.Join(cont.GetMetadata().Tags, ","),
			token.ConvertIDToName(cont.GetHeader().TokenType),
			integrity.ConvertIDToName(cont.GetHeader().IntegrityProviderType),
			integrity.ConvertIDToName(cont.GetHeader().CompressionType),
			cont.GetHeader().Shares,
			cont.GetHeader().Threshold,
		)
	case lib.WriterFormatJSON:
		msg = Information{
			Name:                  containerName,
			Version:               cont.GetHeader().Version,
			CreatedAt:             cont.GetMetadata().CreatedAt.Format(time.DateTime),
			UpdatedAt:             cont.GetMetadata().UpdatedAt.Format(time.DateTime),
			Comment:               cont.GetMetadata().Comment,
			Tags:                  cont.GetMetadata().Tags,
			TokenType:             token.ConvertIDToName(cont.GetHeader().TokenType),
			IntegrityProviderType: integrity.ConvertIDToName(cont.GetHeader().IntegrityProviderType),
			CompressionType:       compression.ConvertIDToName(cont.GetHeader().CompressionType),
			Shares:                cont.GetHeader().Shares,
			Threshold:             cont.GetHeader().Threshold,
		}
	}

	if _, err = lib.WriteFormatted(writer, *opts.InfoWriter.Format, msg); err != nil {
		return lib.IOErr(
			lib.CategoryContainer,
			lib.ErrCodeSealWriteTokenMasterError,
			lib.ErrMessageSealWriteTokenMasterError,
			"",
			err,
		)
	}

	return nil
}
