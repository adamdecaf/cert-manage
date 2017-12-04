package cmd

type Config struct {
	// If we should only show the certificate count, rather than each one
	Count bool

	// What format to print certificates in, formats are defined in ../main.go and
	// checked in print.go
	Format string

	// DryRun won't delete and certificates, but signals to produce a diff instead
	DryRun bool
}
