package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

type JSONL struct {
	file *os.File
	buf  *bufio.Writer
	mu   sync.Mutex
}

func Open(path string) (*JSONL, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open log %q: %w", path, err)
	}
	return &JSONL{file: file, buf: bufio.NewWriterSize(file, 64*1024)}, nil
}

func (w *JSONL) Write(value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode JSON event: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, err := w.buf.Write(data); err != nil {
		return fmt.Errorf("write JSON event: %w", err)
	}
	if err := w.buf.WriteByte('\n'); err != nil {
		return fmt.Errorf("write JSON event separator: %w", err)
	}
	return w.buf.Flush()
}

func (w *JSONL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.buf.Flush(); err != nil {
		_ = w.file.Close()
		return err
	}
	return w.file.Close()
}
