package reader

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lenny/caddy-analyzer/pkg/types"
)

type LogReader interface {
	Read(ctx context.Context) (<-chan string, error)
	Name() string
}

func FromSource(src types.LogSource) LogReader {
	switch src.Type {
	case types.SourceStdin:
		return &StdinReader{}
	case types.SourceFile:
		return &FileReader{paths: expandPaths(src.Path)}
	case types.SourceDocker:
		return &DockerReader{container: src.Path}
	case types.SourceK8s:
		return &K8sReader{pod: src.Path, namespace: src.Namespace}
	case types.SourceJournalctl:
		return &JournalctlReader{unit: src.Path}
	default:
		return &FileReader{paths: expandPaths(src.Path)}
	}
}

func ParseSource(raw string) types.LogSource {
	if raw == "-" {
		return types.LogSource{Type: types.SourceStdin}
	}

	parts := strings.SplitN(raw, "://", 2)
	if len(parts) == 2 {
		switch parts[0] {
		case "docker":
			return types.LogSource{Type: types.SourceDocker, Path: parts[1]}
		case "k8s":
			return types.LogSource{Type: types.SourceK8s, Path: parts[1]}
		case "journalctl":
			return types.LogSource{Type: types.SourceJournalctl, Path: parts[1]}
		}
	}

	return types.LogSource{Type: types.SourceFile, Path: raw}
}

func expandPaths(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return []string{pattern}
	}
	return matches
}

func newLineChannel(ctx context.Context) chan string {
	return make(chan string, 1000)
}

type StdinReader struct{}

func (r *StdinReader) Name() string { return "stdin" }

func (r *StdinReader) Read(ctx context.Context) (<-chan string, error) {
	out := newLineChannel(ctx)
	go func() {
		defer close(out)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			select {
			case out <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

type FileReader struct {
	paths []string
}

func (r *FileReader) Name() string {
	if len(r.paths) == 1 {
		return r.paths[0]
	}
	return fmt.Sprintf("%d files", len(r.paths))
}

func (r *FileReader) Read(ctx context.Context) (<-chan string, error) {
	out := newLineChannel(ctx)
	go func() {
		defer close(out)
		for _, path := range r.paths {
			if err := readFileLines(ctx, path, out); err != nil {
				fmt.Fprintf(os.Stderr, "error reading %s: %v\n", path, err)
			}
		}
	}()
	return out, nil
}

func readFileLines(ctx context.Context, path string, out chan<- string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case out <- scanner.Text():
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return scanner.Err()
}

type DockerReader struct {
	container string
}

func (r *DockerReader) Name() string { return "docker:" + r.container }

func (r *DockerReader) Read(ctx context.Context) (<-chan string, error) {
	out := newLineChannel(ctx)
	args := []string{"logs", "-f"}
	if !isTerminal() {
		args = append(args, "--tail=all")
	}
	args = append(args, r.container)

	cmd := exec.CommandContext(ctx, "docker", args...)
	return execLines(ctx, cmd, out)
}

type K8sReader struct {
	pod       string
	namespace string
}

func (r *K8sReader) Name() string {
	ns := r.namespace
	if ns == "" {
		ns = "default"
	}
	return fmt.Sprintf("k8s:%s (ns:%s)", r.pod, ns)
}

func (r *K8sReader) Read(ctx context.Context) (<-chan string, error) {
	out := newLineChannel(ctx)
	args := []string{"logs", "--tail=-1"}
	if r.namespace != "" {
		args = append(args, "-n", r.namespace)
	}
	args = append(args, r.pod)

	cmd := exec.CommandContext(ctx, "kubectl", args...)
	return execLines(ctx, cmd, out)
}

type JournalctlReader struct {
	unit string
}

func (r *JournalctlReader) Name() string { return "journalctl:" + r.unit }

func (r *JournalctlReader) Read(ctx context.Context) (<-chan string, error) {
	out := newLineChannel(ctx)
	cmd := exec.CommandContext(ctx, "journalctl", "-u", r.unit, "--output=json", "--follow")
	return execLines(ctx, cmd, out)
}

func execLines(ctx context.Context, cmd *exec.Cmd, out chan string) (<-chan string, error) {
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start command: %w", err)
	}

	go func() {
		defer close(out)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			select {
			case out <- scanner.Text():
			case <-ctx.Done():
				cmd.Process.Kill()
				return
			}
		}
		cmd.Wait()
	}()

	return out, nil
}

func isTerminal() bool {
	stat, _ := os.Stdin.Stat()
	return (stat.Mode() & os.ModeCharDevice) != 0
}
