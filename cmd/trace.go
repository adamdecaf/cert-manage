package cmd

import (
	"os"
	"runtime/trace"
)

func NewTrace(where string) (*Trace, error) {
	if where == "" {
		return nil, nil
	}

	fd, err := os.Create(where)
	if err != nil {
		return nil, err
	}

	return &Trace{
		fd: fd,
	}, nil
}

type Trace struct {
	fd *os.File
}

func (t *Trace) Start() error {
	if t == nil {
		return nil
	}
	return trace.Start(t.fd)
}

func (t *Trace) Stop() error {
	if t == nil {
		return nil
	}

	trace.Stop()
	return t.fd.Close()
}
