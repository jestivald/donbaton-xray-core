package inbound

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
)

func testHandler() *Handler {
	return &Handler{validator: new(vless.MemoryValidator)}
}

func testUser(email string) *protocol.MemoryUser {
	return &protocol.MemoryUser{Email: email, Account: &vless.MemoryAccount{ID: protocol.NewID(uuid.New())}}
}

func addTestUser(t *testing.T, h *Handler, user *protocol.MemoryUser) *protocol.MemoryUser {
	t.Helper()
	if err := h.AddUser(context.Background(), user); err != nil {
		t.Fatal(err)
	}
	return h.GetUser(context.Background(), user.Email)
}

func testPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() { conn.Close(); peer.Close() })
	return conn, peer
}

func assertClosed(t *testing.T, peer net.Conn) {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	_, err := peer.Read(make([]byte, 1))
	if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("connection was not closed: %v", err)
	}
}

func assertWorking(t *testing.T, conn, peer net.Conn) {
	t.Helper()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	written := make(chan error, 1)
	go func() { _, err := conn.Write([]byte{42}); written <- err }()
	got := make([]byte, 1)
	if _, err := io.ReadFull(peer, got); err != nil || got[0] != 42 {
		t.Fatalf("unaffected connection stopped: %v", err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Time{})
}

func TestRemoveUserClosesOnlyItsConnectionsOnThisInbound(t *testing.T) {
	lte, wifi := testHandler(), testHandler()
	subject := testUser("Subject@Probe")
	lteSubject := addTestUser(t, lte, subject)
	wifiSubject := addTestUser(t, wifi, subject)
	control := addTestUser(t, lte, testUser("Control@Probe"))
	var revokedPeers []net.Conn
	for range 3 { // Includes several logical streams from the same account/IP.
		conn, peer := testPipe(t)
		unregister, err := lte.registerUserConnection(lteSubject, conn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(unregister)
		revokedPeers = append(revokedPeers, peer)
	}
	controlConn, controlPeer := testPipe(t)
	wifiConn, wifiPeer := testPipe(t)
	for _, entry := range []struct {
		h    *Handler
		user *protocol.MemoryUser
		conn net.Conn
	}{
		{lte, control, controlConn}, {wifi, wifiSubject, wifiConn},
	} {
		unregister, err := entry.h.registerUserConnection(entry.user, entry.conn)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(unregister)
	}
	if err := lte.RemoveUser(context.Background(), "sUbJeCt@PrObE"); err != nil {
		t.Fatal(err)
	}
	for _, peer := range revokedPeers {
		assertClosed(t, peer)
	}
	assertWorking(t, controlConn, controlPeer)
	assertWorking(t, wifiConn, wifiPeer)
	if lte.GetUser(context.Background(), subject.Email) != nil {
		t.Fatal("removed credential is still authorized")
	}
}

func TestRegistrationRejectsAuthenticationFromRemovedGeneration(t *testing.T) {
	h := testHandler()
	supplied := testUser("reused@probe")
	old := addTestUser(t, h, supplied)
	oldConn, oldPeer := testPipe(t)
	unregisterOld, err := h.registerUserConnection(old, oldConn)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveUser(context.Background(), old.Email); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, oldPeer)
	current := addTestUser(t, h, supplied) // Same original object, UUID and email.
	lateConn, _ := testPipe(t)
	if _, err := h.registerUserConnection(old, lateConn); err == nil {
		t.Fatal("old authenticated request was admitted after remove/re-add")
	}
	newConn, newPeer := testPipe(t)
	unregisterNew, err := h.registerUserConnection(current, newConn)
	if err != nil {
		t.Fatal(err)
	}
	defer unregisterNew()
	unregisterOld() // A previous generation must not erase the new registration.
	assertWorking(t, newConn, newPeer)
	if err := h.RemoveUser(context.Background(), current.Email); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, newPeer)
}

func TestRegistrationRacingRemovalCannotLeaveARegisteredConnection(t *testing.T) {
	for range 200 {
		h := testHandler()
		user := addTestUser(t, h, testUser("racing@probe"))
		conn, peer := testPipe(t)
		start := make(chan struct{})
		registered := make(chan error, 1)
		removed := make(chan error, 1)
		go func() {
			<-start
			_, err := h.registerUserConnection(user, conn)
			registered <- err
		}()
		go func() { <-start; removed <- h.RemoveUser(context.Background(), user.Email) }()
		close(start)
		if err := <-removed; err != nil {
			t.Fatal(err)
		}
		if err := <-registered; err == nil {
			assertClosed(t, peer)
		}
		h.userConnections.mu.Lock()
		remaining := len(h.userConnections.users)
		h.userConnections.mu.Unlock()
		if remaining != 0 {
			t.Fatal("connection survived successful removal")
		}
	}
}

type unregisteringConnection struct {
	net.Conn
	unregister func()
}

func (c *unregisteringConnection) Close() error {
	c.unregister()
	return c.Conn.Close()
}

func TestCloseRunsOutsideRegistryLock(t *testing.T) {
	h := testHandler()
	user := addTestUser(t, h, testUser("unregister@probe"))
	conn, peer := testPipe(t)
	wrapped := &unregisteringConnection{Conn: conn}
	unregister, err := h.registerUserConnection(user, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	wrapped.unregister = unregister
	done := make(chan error, 1)
	go func() { done <- h.RemoveUser(context.Background(), user.Email) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("RemoveUser deadlocked while the connection unregistered")
	}
	assertClosed(t, peer)
}

func TestNormalCompletionDoesNotRetainConnection(t *testing.T) {
	h := testHandler()
	user := addTestUser(t, h, testUser("finished@probe"))
	conn, peer := testPipe(t)
	unregister, err := h.registerUserConnection(user, conn)
	if err != nil {
		t.Fatal(err)
	}
	unregister()
	unregister() // Cleanup is idempotent.
	if err := h.RemoveUser(context.Background(), user.Email); err != nil {
		t.Fatal(err)
	}
	assertWorking(t, conn, peer) // Removal did not act on a released connection.
}

func TestCloseHandlerClosesAllAndRejectsNewRegistrations(t *testing.T) {
	h := testHandler()
	user := addTestUser(t, h, testUser("closing@probe"))
	conn, peer := testPipe(t)
	unregister, err := h.registerUserConnection(user, conn)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, peer)
	unregister()
	if _, err := h.registerUserConnection(user, conn); err == nil {
		t.Fatal("closed handler admitted connection")
	}
	if err := h.AddUser(context.Background(), testUser("new@probe")); err == nil {
		t.Fatal("closed handler admitted user")
	}
}

func TestUnknownRemovalDoesNotCloseOtherUsers(t *testing.T) {
	h := testHandler()
	user := addTestUser(t, h, testUser("remaining@probe"))
	conn, peer := testPipe(t)
	unregister, err := h.registerUserConnection(user, conn)
	if err != nil {
		t.Fatal(err)
	}
	defer unregister()
	if err := h.RemoveUser(context.Background(), "missing@probe"); err == nil {
		t.Fatal("missing user removal succeeded")
	}
	assertWorking(t, conn, peer)
}

func TestConcurrentCleanupAndHandlerClose(t *testing.T) {
	h := testHandler()
	var wait sync.WaitGroup
	start := make(chan struct{})
	for i := range 50 {
		user := testUser("cleanup-" + strconv.Itoa(i) + "@probe")
		user = addTestUser(t, h, user)
		conn, _ := testPipe(t)
		unregister, err := h.registerUserConnection(user, conn)
		if err != nil {
			t.Fatal(err)
		}
		wait.Add(1)
		go func() { defer wait.Done(); <-start; unregister() }()
	}
	close(start)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	if len(h.userConnections.users) != 0 {
		t.Fatal("handler close left retained users")
	}
}
