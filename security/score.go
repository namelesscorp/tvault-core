package security

import (
	"math"
	"path/filepath"
	"strings"

	"github.com/namelesscorp/tvault-core/compression"
	"github.com/namelesscorp/tvault-core/integrity"
	"github.com/namelesscorp/tvault-core/token"
)

const (
	SensitiveFiles              = "sensitive_files"
	IntegrityProvider           = "integrity_provider"
	Token                       = "token"
	Compression                 = "compression"
	Shares                      = "shares"
	Thresholds                  = "thresholds"
	ContainerPassphrase         = "container_passphrase"
	IntegrityProviderPassphrase = "integrity_provider_passphrase"

	LevelExcellent = "excellent"
	LevelGood      = "good"
	LevelModerate  = "moderate"
	LevelWeak      = "weak"
	LevelCritical  = "critical"
)

var (
	sensitiveExtensions = map[string]bool{
		".key":      true,
		".pem":      true,
		".crt":      true,
		".password": true,
		".secret":   true,
		".env":      true,
		".config":   true,
		".settings": true,
		".log":      true,
	}

	sensitiveFilePatterns = []string{
		"password", "passwords", "secret", "secrets", "key", "keys", "token", "tokens", "credential", "credentials",
		"auth", "private", "cert", "certs", "certificates", "certificate", "sensitive",
	}
)

type (
	Score interface {
		Calculate() float64
		Level() string
		Details() map[string]float64
	}

	score struct {
		params Params
		weight *weight
	}

	weight struct {
		sensitiveFiles              float64
		integrityProvider           float64
		token                       float64
		compression                 float64
		shares                      float64
		thresholds                  float64
		containerPassphrase         float64
		integrityProviderPassphrase float64
	}

	Params struct {
		TokenType                   string
		IntegrityProviderType       string
		CompressionType             string
		NumberOfShares              int
		NumberOfThreshold           int
		ContainerPassphrase         string
		IntegrityProviderPassphrase string
		FileNameList                []string
	}
)

func New(params Params) Score {
	return score{
		params: params,
		weight: &weight{
			sensitiveFiles:              0.10,
			integrityProvider:           0.15,
			token:                       0.15,
			compression:                 0.05,
			shares:                      0.15,
			thresholds:                  0.10,
			containerPassphrase:         0.15,
			integrityProviderPassphrase: 0.15,
		},
	}
}

func (s score) Calculate() float64 {
	details := s.Details()

	total := 0.0
	total += details[SensitiveFiles] * s.weight.sensitiveFiles
	total += details[IntegrityProvider] * s.weight.integrityProvider
	total += details[Token] * s.weight.token
	total += details[Compression] * s.weight.compression
	total += details[Shares] * s.weight.shares
	total += details[Thresholds] * s.weight.thresholds
	total += details[ContainerPassphrase] * s.weight.containerPassphrase
	total += details[IntegrityProviderPassphrase] * s.weight.integrityProviderPassphrase

	return math.Round(total*100) / 100
}

func (s score) Level() string {
	sc := s.Calculate()

	switch {
	case sc >= 0.9:
		return LevelExcellent
	case sc >= 0.7:
		return LevelGood
	case sc >= 0.5:
		return LevelModerate
	case sc >= 0.3:
		return LevelWeak
	default:
		return LevelCritical
	}
}

func (s score) Details() map[string]float64 {
	return map[string]float64{
		SensitiveFiles:              s.scoreSensitiveFiles(),
		IntegrityProvider:           s.scoreIntegrityProvider(),
		Token:                       s.scoreToken(),
		Compression:                 s.scoreCompression(),
		Shares:                      s.scoreShares(),
		Thresholds:                  s.scoreThresholds(),
		ContainerPassphrase:         s.scorePassphrase(s.params.ContainerPassphrase),
		IntegrityProviderPassphrase: s.scorePassphrase(s.params.IntegrityProviderPassphrase),
	}
}

// scoreSensitiveFiles - returns 1.0 if any sensitive files are present (meaning the
// data is valuable and other protections matter more), 0.0 otherwise.
func (s score) scoreSensitiveFiles() float64 {
	for _, name := range s.params.FileNameList {
		ext := strings.ToLower(filepath.Ext(name))
		if sensitiveExtensions[ext] {
			return 1.0
		}

		baseName := strings.ToLower(filepath.Base(name))
		for _, pattern := range sensitiveFilePatterns {
			if strings.Contains(baseName, pattern) {
				return 1.0
			}
		}
	}

	return 0.0
}

// scoreIntegrityProvider - scores the integrity provider choice.
func (s score) scoreIntegrityProvider() float64 {
	switch s.params.IntegrityProviderType {
	case integrity.TypeNameEd25519:
		return 1.0
	case integrity.TypeNameHMAC:
		return 0.7
	case integrity.TypeNameNone:
		return 0.0
	default:
		return 0.0
	}
}

// scoreToken - scores the token type.
func (s score) scoreToken() float64 {
	switch s.params.TokenType {
	case token.TypeNameShare:
		return 1.0
	case token.TypeNameMaster:
		return 0.5
	case token.TypeNameNone:
		return 0.0
	default:
		return 0.0
	}
}

// scoreCompression - scores whether compression is used (obfuscates internal structure).
func (s score) scoreCompression() float64 {
	switch s.params.CompressionType {
	case compression.TypeNameZip:
		return 1.0
	case compression.TypeNameNone:
		return 0.0
	default:
		return 0.0
	}
}

// scoreShares - scores the number of Shamir shares (more = better distribution).
func (s score) scoreShares() float64 {
	if s.params.NumberOfShares <= 0 {
		return 0.0
	}

	return math.Min(float64(s.params.NumberOfShares)/5.0, 1.0)
}

// scoreThresholds - scores the threshold/shares ratio.
// Higher ratio = stricter quorum requirement = more secure.
func (s score) scoreThresholds() float64 {
	if s.params.NumberOfShares <= 0 || s.params.NumberOfThreshold <= 0 {
		return 0.0
	}

	ratio := float64(s.params.NumberOfThreshold) / float64(s.params.NumberOfShares)
	return math.Min(ratio, 1.0)
}

// scorePassphrase - scores passphrase strength by length.
func (s score) scorePassphrase(passphrase string) float64 {
	n := len(passphrase)
	switch {
	case n == 0:
		return 0.0
	case n < 8:
		return 0.3
	case n < 16:
		return 0.6
	case n < 24:
		return 0.8
	default:
		return 1.0
	}
}
