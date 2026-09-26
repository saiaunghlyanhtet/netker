package oci

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

var ErrNotExist = errors.New("container does not exist in the OCI runtime")

// Runtime drives an OCI runtime binary.
type Runtime struct {
	Bin           string // crun or runc
	Root          string // runtime state directory (--root)
	CgroupManager string // optional --cgroup-manager (crun only)
}

func (r *Runtime) cmd(args ...string) *exec.Cmd {
	base := []string{"--root", r.Root}
	if r.CgroupManager != "" {
		base = append(base, "--cgroup-manager="+r.CgroupManager)
	}
	return exec.Command(r.Bin, append(base, args...)...)
}

func (r *Runtime) run(args ...string) error {
	c := r.cmd(args...)
	var stderr bytes.Buffer
	c.Stderr = &stderr
	if err := c.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if strings.Contains(msg, "does not exist") || strings.Contains(msg, "No such file") {
			return fmt.Errorf("%s: %w", msg, ErrNotExist)
		}
		return fmt.Errorf("%s %s: %w: %s", r.Bin, args[0], err, msg)
	}
	return nil
}

// WriteSpec writes config.json into bundle.
func WriteSpec(bundle string, s *specs.Spec) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(bundle+"/config.json", data, 0o644)
}

// RunDetached starts the container in the background. The container's
// stdout and stderr go to log; stdin is /dev/null.
func (r *Runtime) RunDetached(id, bundle string, log *os.File) error {
	c := r.cmd("run", "--detach", "--bundle", bundle, id)
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer devnull.Close()
	// Only *os.File values here: for anything else exec.Cmd creates a pipe
	// and waits for EOF, which never comes because the container inherits
	// the write end. crun's own errors therefore land in the log.
	start, _ := log.Seek(0, io.SeekEnd)
	c.Stdin, c.Stdout, c.Stderr = devnull, log, log
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s run: %w: %s", r.Bin, err, tailFrom(log.Name(), start))
	}
	return nil
}

// tailFrom returns what was appended to the file after offset, trimmed.
func tailFrom(path string, offset int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	f.Seek(offset, io.SeekStart)
	b, _ := io.ReadAll(io.LimitReader(f, 4096))
	return strings.TrimSpace(string(b))
}

// RunForeground runs the container attached to the given stdio and returns
// its exit code.
func (r *Runtime) RunForeground(id, bundle string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	c := r.cmd("run", "--bundle", bundle, id)
	c.Stdin, c.Stdout, c.Stderr = stdin, stdout, stderr
	return exitCode(c.Run())
}

// Exec runs a process in a running container attached to the given stdio.
func (r *Runtime) Exec(id string, tty bool, env []string, cwd string, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	a := []string{"exec"}
	if tty {
		a = append(a, "--tty")
	}
	for _, e := range env {
		a = append(a, "--env", e)
	}
	if cwd != "" {
		a = append(a, "--cwd", cwd)
	}
	a = append(a, id)
	a = append(a, args...)
	c := r.cmd(a...)
	c.Stdin, c.Stdout, c.Stderr = stdin, stdout, stderr
	return exitCode(c.Run())
}

func exitCode(err error) (int, error) {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// State is the subset of the OCI state we use.
type State struct {
	Status string `json:"status"` // creating, created, running, stopped
	Pid    int    `json:"pid"`
}

func (r *Runtime) State(id string) (State, error) {
	c := r.cmd("state", id)
	var stdout, stderr bytes.Buffer
	c.Stdout, c.Stderr = &stdout, &stderr
	if err := c.Run(); err != nil {
		return State{}, fmt.Errorf("%s: %w", strings.TrimSpace(stderr.String()), ErrNotExist)
	}
	var s State
	if err := json.Unmarshal(stdout.Bytes(), &s); err != nil {
		return State{}, err
	}
	return s, nil
}

func (r *Runtime) Kill(id, signal string) error { return r.run("kill", id, signal) }

// Delete removes the runtime's state for id; force kills it first.
func (r *Runtime) Delete(id string, force bool) error {
	if force {
		return r.run("delete", "--force", id)
	}
	return r.run("delete", id)
}
