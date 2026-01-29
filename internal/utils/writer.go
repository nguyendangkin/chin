package utils

import "io"

// CountingWriter counts the number of bytes written to it.
type CountingWriter struct {
	Writer   io.Writer
	Count    uint64
	Callback func(int) // Optional callback
}

func (w *CountingWriter) Write(p []byte) (n int, err error) {
	n, err = w.Writer.Write(p)
	w.Count += uint64(n)
	if w.Callback != nil {
		w.Callback(n)
	}
	return
}
