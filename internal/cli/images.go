package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func pullCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pull IMAGE",
		Short: "Download an image from a registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := manager().Images.Pull(args[0], cmd.OutOrStdout())
			return err
		},
	}
}

func imagesCmd() *cobra.Command {
	var quiet bool
	cmd := &cobra.Command{
		Use:   "images [OPTIONS]",
		Short: "List images",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			imgs, err := manager().Images.List()
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if quiet {
				for _, i := range imgs {
					fmt.Fprintln(out, imageID(i.Digest))
				}
				return nil
			}
			tw := tabwriter.NewWriter(out, 0, 4, 3, ' ', 0)
			fmt.Fprintln(tw, "REPOSITORY\tTAG\tIMAGE ID\tPULLED\tSIZE")
			for _, i := range imgs {
				repo, tag := splitRef(shortImage(i.Ref))
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", repo, tag, imageID(i.Digest), ago(i.Pulled), humanSize(i.Size))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Only show image IDs")
	return cmd
}

func rmiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rmi IMAGE...",
		Short: "Remove one or more images",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			m := manager()
			for _, ref := range args {
				if err := m.Images.Remove(ref, m.ImageInUse); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Deleted:", ref)
			}
			return nil
		},
	}
}

func imageID(digest string) string {
	d := strings.TrimPrefix(digest, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

func splitRef(ref string) (string, string) {
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[:i], ref[i+1:]
	}
	return ref, "<none>"
}

func humanSize(n int64) string {
	units := []string{"B", "kB", "MB", "GB"}
	f := float64(n)
	i := 0
	for f >= 1000 && i < len(units)-1 {
		f /= 1000
		i++
	}
	return fmt.Sprintf("%.3g%s", f, units[i])
}
