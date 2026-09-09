package splithttp

import (
	"bytes"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/signal/done"
)

func TestLogicalConnectionCloseDoesNotCloseAnotherXHTTPSession(t *testing.T) {
	makeConn := func() (*splitConn, *httpServerConn, *uploadQueue) {
		writer := &httpServerConn{Instance: done.New(), Reader: bytes.NewReader(nil), ResponseWriter: httptest.NewRecorder()}
		queue := NewUploadQueue(4)
		return &splitConn{writer: writer, reader: queue}, writer, queue
	}
	subject, subjectDown, subjectUp := makeConn()
	control, controlDown, controlUp := makeConn()
	defer control.Close()
	if err := subject.Close(); err != nil {
		t.Fatal(err)
	}
	if !subjectDown.Done() {
		t.Fatal("subject download did not receive cancellation")
	}
	if _, err := subjectUp.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("subject upload remains readable: %v", err)
	}
	if err := subjectUp.Push(Packet{Payload: []byte("late"), Seq: 0}); err == nil {
		t.Fatal("revoked upload accepted a later packet")
	}
	if controlDown.Done() {
		t.Fatal("control download was cancelled")
	}
	if err := controlUp.Push(Packet{Payload: []byte("ok"), Seq: 0}); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(controlUp, buf); err != nil || string(buf) != "ok" {
		t.Fatalf("control upload interrupted: %v", err)
	}
	if _, err := control.Write([]byte("still working")); err != nil {
		t.Fatal(err)
	}
}

type stalledResponseWriter struct {
	*httptest.ResponseRecorder
	writing chan struct{}
	unblock chan struct{}
	once    sync.Once
}

func (w *stalledResponseWriter) Write(p []byte) (int, error) {
	close(w.writing)
	<-w.unblock
	return 0, io.ErrClosedPipe
}

func (w *stalledResponseWriter) SetWriteDeadline(time.Time) error {
	w.once.Do(func() { close(w.unblock) })
	return nil
}

func TestLogicalConnectionCloseInterruptsBlockedWrite(t *testing.T) {
	writer := &stalledResponseWriter{ResponseRecorder: httptest.NewRecorder(), writing: make(chan struct{}), unblock: make(chan struct{})}
	conn := &httpServerConn{Instance: done.New(), Reader: bytes.NewReader(nil), ResponseWriter: writer}
	writeDone := make(chan struct{})
	go func() { _, _ = conn.Write([]byte("download")); close(writeDone) }()
	<-writer.writing
	closeDone := make(chan struct{})
	go func() { _ = conn.Close(); close(closeDone) }()
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		writer.SetWriteDeadline(time.Now())
		t.Fatal("revocation blocked behind a stalled HTTP response")
	}
	<-writeDone
	if !conn.Done() {
		t.Fatal("download was not cancelled")
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}
