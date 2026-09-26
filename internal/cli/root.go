// Package cli implements the docker-compatible netker command line.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/saiaunghlyanhtet/netker/internal/config"
	"github.com/saiaunghlyanhtet/netker/internal/container"
)

// Version is set at build time with -ldflags "-X .../cli.Version=...".
var Version = "dev"

// ExitError makes netker exit with a container's exit code.
type ExitError struct{ Code int }

func (e ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

func manager() *container.Manager { return container.NewManager(config.DefaultPaths()) }

func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:           "netker",
		Short:         "Docker-compatible containers networked with Linux netkit devices",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		runCmd(), createCmd(), startCmd(), stopCmd(), killCmd(), restartCmd(), rmCmd(),
		psCmd(), execCmd(), logsCmd(), inspectCmd(), portCmd(),
		pullCmd(), imagesCmd(), rmiCmd(),
		networkCmd(), systemCmd(), versionCmd(), probeCmd(),
	)
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	err := NewRoot().Execute()
	var ee ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	return 0
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the netker version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "netker %s (OCI runtime: %s)\n", Version, config.Runtime())
		},
	}
}

func printJSON(cmd *cobra.Command, v any) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// forEach runs fn for every container reference and reports failures the way
// docker does: keep going, print each error, fail at the end.
func forEach(cmd *cobra.Command, refs []string, fn func(*container.Manager, *container.Container) error) error {
	m := manager()
	failed := false
	for _, ref := range refs {
		c, err := m.Get(ref)
		if err == nil {
			err = fn(m, c)
		}
		if err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), "Error:", err)
			failed = true
			continue
		}
		fmt.Fprintln(cmd.OutOrStdout(), ref)
	}
	if failed {
		return ExitError{Code: 1}
	}
	return nil
}
