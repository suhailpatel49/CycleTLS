package cycletls

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	http "github.com/Danny-Dasilva/fhttp"
)

func TestFullRequestQueueRejectsAndCleansRequest(t *testing.T) {
	originalPendingSlots := pendingRequestSlots
	pendingRequestSlots = make(chan struct{}, 1)
	pendingRequestSlots <- struct{}{}
	defer func() { pendingRequestSlots = originalPendingSlots }()

	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	requestID := "queue-overflow"
	state := trackRequest(requestID, cancel)
	var ownerRequests sync.Map
	ownerRequests.Store(requestID, struct{}{})

	chanRead := make(chan fullRequest, 1)
	chanWrite := make(chan []byte, 1)
	chanRead <- fullRequest{
		req:           req,
		options:       cycleTLSRequest{RequestID: requestID},
		state:         state,
		ownerRequests: &ownerRequests,
	}
	close(chanRead)
	readProcess(chanRead, chanWrite)

	frame := <-chanWrite
	if !bytes.Contains(frame, []byte("CycleTLS request queue is full")) {
		t.Fatalf("expected queue-full response, got %q", frame)
	}
	activeRequestsMutex.Lock()
	_, active := activeRequests[requestID]
	activeRequestsMutex.Unlock()
	if active {
		t.Fatal("rejected request remained active")
	}
	if _, owned := ownerRequests.Load(requestID); owned {
		t.Fatal("rejected request remained owned by the socket")
	}
}

func TestCanceledQueuedRequestDoesNotBlockReader(t *testing.T) {
	originalSlots := requestSlots
	requestSlots = make(chan struct{}, 1)
	requestSlots <- struct{}{}
	defer func() { requestSlots = originalSlots }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	chanRead := make(chan fullRequest, 1)
	chanWrite := make(chan []byte, 1)
	chanRead <- fullRequest{req: req}
	close(chanRead)
	done := make(chan struct{})
	go func() {
		readProcess(chanRead, chanWrite)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		<-requestSlots
		<-done
		t.Fatal("canceled request remained blocked behind the concurrency limit")
	}
}
