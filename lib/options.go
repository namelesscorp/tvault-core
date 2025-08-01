package lib

type (
	Writer struct {
		Type   *string
		Path   *string
		Format *string
	}

	Reader struct {
		Type   *string
		Path   *string
		Flag   *string
		Format *string
	}

	Shamir struct {
		Shares    *int
		Threshold *int
		IsEnabled *bool
	}

	IntegrityProvider struct {
		Type              *string
		CurrentPassphrase *string
		NewPassphrase     *string
	}

	Compression struct {
		Type *string
	}

	Container struct {
		NewPath     *string
		CurrentPath *string
		FolderPath  *string
		Passphrase  *string
	}
)
