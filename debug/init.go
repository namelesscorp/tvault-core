//go:build debug

package debug

func init() {
	defaultDebug = New(defaultProfileDir)
	if err := defaultDebug.Start(); err != nil {
		return
	}

	defaultDebug.SetupSignalHandler()
}
