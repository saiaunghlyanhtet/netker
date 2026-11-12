// Package cli implements the docker-compatible netker command line.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"

	"github.com/saiaunghlyanhtet/netker/internal/config"
	"github.com/saiaunghlyanhtet/netker/internal/container"
)

// Version is set at build time with -ldflags "-X .../cli.Version=...", as
// make build does. Builds without it (go build, go install) report the
// version Go recorded in the binary instead; see version.
var Version = "dev"

// version is the version netker reports: Version when the build set it,
// otherwise the module version Go stamps into the binary (a tag for go
// install ...@v0.1.0, a pseudo-version for go build in a git checkout), or
// else the git commit it was built from.
func version() string {
	bi, _ := debug.ReadBuildInfo()
	return versionFrom(Version, bi)
}

func versionFrom(ldflags string, bi *debug.BuildInfo) string {
	if ldflags != "dev" && ldflags != "" {
		return ldflags
	}
	if bi == nil {
		return "dev"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev string
	var dirty bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev == "" {
		return "dev"
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		rev += "-dirty"
	}
	return "dev-" + rev
}

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
		psCmd(), execCmd(), logsCmd(), inspectCmd(), portCmd(), statsCmd(),
		pullCmd(), imagesCmd(), rmiCmd(),
		networkCmd(), netCmd(), systemCmd(), versionCmd(), probeCmd(),
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
			fmt.Fprintf(cmd.OutOrStdout(), "netker %s (OCI runtime: %s)\n", version(), config.Runtime())
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
