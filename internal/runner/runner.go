package runner

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
)

type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type OS struct {
	DryRun bool
	Record func(string)
}

func (r OS) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if r.Record != nil {
		r.Record(fmt.Sprintf("%s %q", name, args))
	}
	if r.DryRun {
		return nil, nil
	}
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- executable and args are separate trusted installer values.
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		return output.Bytes(), fmt.Errorf("%s: %w", name, err)
	}
	return output.Bytes(), nil
}

type Fake struct {
	Calls   [][]string
	Results map[string][]byte
	Errors  map[string]error
}

func (r *Fake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	r.Calls = append(r.Calls, call)
	if err := r.Errors[name]; err != nil {
		return r.Results[name], err
	}
	return r.Results[name], nil
}
