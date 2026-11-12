package cli

import (
	"runtime/debug"
	"testing"
)

func TestVersionFrom(t *testing.T) {
	vcs := func(rev, modified string) []debug.BuildSetting {
		return []debug.BuildSetting{
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: rev},
			{Key: "vcs.modified", Value: modified},
		}
	}
	const rev = "65e81eaab0d890c35aece12a53bbab40f16a3337"
	for _, tc := range []struct {
		name    string
		ldflags string
		bi      *debug.BuildInfo
		want    string
	}{
		{"make build", "v0.1.0-rc.1-3-g65e81ea", &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}}, "v0.1.0-rc.1-3-g65e81ea"},
		{"go install @tag", "dev", &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}}, "v0.1.0"},
		{"go build in a checkout", "dev", &debug.BuildInfo{
			Main:     debug.Module{Version: "v0.1.0-rc.1.0.20261108005500-65e81eaab0d8+dirty"},
			Settings: vcs(rev, "true"),
		}, "v0.1.0-rc.1.0.20261108005500-65e81eaab0d8+dirty"},
		{"no module version", "dev", &debug.BuildInfo{
			Main:     debug.Module{Version: "(devel)"},
			Settings: vcs(rev, "false"),
		}, "dev-65e81eaab0d8"},
		{"no module version, dirty", "dev", &debug.BuildInfo{
			Main:     debug.Module{Version: "(devel)"},
			Settings: vcs(rev, "true"),
		}, "dev-65e81eaab0d8-dirty"},
		{"no vcs info", "dev", &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "dev"},
		{"no build info", "dev", nil, "dev"},
	} {
		if got := versionFrom(tc.ldflags, tc.bi); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
