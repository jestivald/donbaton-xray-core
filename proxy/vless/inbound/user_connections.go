package inbound

import (
	"sync"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Track logical inbound connections, not source IPs or shared transport sockets.
// For XHTTP each connection is one splitConn, even when several users share a
// reverse proxy or HTTP/2 connection. The MemoryUser pointer is its generation:
// a removed and re-added credential must not admit an already authenticated flow.
type userConnections struct {
	mu     sync.Mutex
	closed bool
	users  map[*protocol.MemoryUser]map[*userConnection]struct{}
}

type userConnection struct {
	connection stat.Connection
}

func (h *Handler) addUser(user *protocol.MemoryUser) error {
	h.userConnections.mu.Lock()
	defer h.userConnections.mu.Unlock()
	if h.userConnections.closed {
		return errors.New("VLESS handler is closed")
	}
	// Give every insertion a separate generation, including an in-process caller
	// reusing its MemoryUser object after RemoveUser.
	owned := *user
	return h.validator.Add(&owned)
}

func (h *Handler) registerUserConnection(user *protocol.MemoryUser, connection stat.Connection) (func(), error) {
	h.userConnections.mu.Lock()
	defer h.userConnections.mu.Unlock()
	if h.userConnections.closed {
		return nil, errors.New("VLESS handler is closed")
	}
	if user == nil || connection == nil {
		return nil, errors.New("invalid VLESS connection")
	}
	account, ok := user.Account.(*vless.MemoryAccount)
	if !ok || account.ID == nil || h.validator.Get(account.ID.UUID()) != user {
		return nil, errors.New("VLESS user was removed before connection registration")
	}
	if h.userConnections.users == nil {
		h.userConnections.users = make(map[*protocol.MemoryUser]map[*userConnection]struct{})
	}
	connections := h.userConnections.users[user]
	if connections == nil {
		connections = make(map[*userConnection]struct{})
		h.userConnections.users[user] = connections
	}
	entry := &userConnection{connection: connection}
	connections[entry] = struct{}{}
	return func() {
		h.userConnections.mu.Lock()
		defer h.userConnections.mu.Unlock()
		if current := h.userConnections.users[user]; current != nil {
			delete(current, entry)
			if len(current) == 0 {
				delete(h.userConnections.users, user)
			}
		}
	}, nil
}

func (h *Handler) removeUser(email string) error {
	h.userConnections.mu.Lock()
	user := h.validator.GetByEmail(email)
	h.RemoveReverse(user)
	if err := h.validator.Del(email); err != nil {
		h.userConnections.mu.Unlock()
		return err
	}
	connections := h.userConnections.users[user]
	delete(h.userConnections.users, user)
	h.userConnections.mu.Unlock()

	// Close outside the lock: the associated Process can finish and unregister.
	// Closing an already finished connection may return net.ErrClosed, which does
	// not undo a successful revocation.
	for entry := range connections {
		_ = entry.connection.Close()
	}
	return nil
}

func (h *Handler) closeUserConnections() {
	h.userConnections.mu.Lock()
	h.userConnections.closed = true
	users := h.userConnections.users
	h.userConnections.users = nil
	h.userConnections.mu.Unlock()
	for _, connections := range users {
		for entry := range connections {
			_ = entry.connection.Close()
		}
	}
}
