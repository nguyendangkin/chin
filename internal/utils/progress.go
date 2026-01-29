package utils

import (
	"fmt"
	"io"
)

func NewProgress(description string, total int64) *Progress {
	fmt.Printf("%s...\n", description)
	return &Progress{total: total}
}

type Progress struct {
	total     int64
	completed int64
}

func (p *Progress) Increment(n int64) {
	p.completed += n
	if p.total > 0 {
		percent := (p.completed * 100) / p.total
		if percent > 100 {
			percent = 100
		}
		fmt.Printf("\r  Progress: %d%% (%d/%d bytes)", percent, p.completed, p.total)
	}
}

func (p *Progress) Finish() {
	fmt.Println("\nDone!")
}

func (p *Progress) StartReader(r io.Reader) io.Reader {
	return &progressReader{reader: r, progress: p}
}

type progressReader struct {
	reader   io.Reader
	progress *Progress
}

func (pr *progressReader) Read(p []byte) (n int, err error) {
	n, err = pr.reader.Read(p)
	if n > 0 {
		pr.progress.Increment(int64(n))
	}
	return
}
