package brokerproto

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"sync"

	"github.com/coder/websocket"
)

// ErrClosed reports a call on a channel that has closed.
var ErrClosed = errors.New("brokerproto: channel closed")

// RemoteError is a refusal from the Control Plane.
type RemoteError string

func (e RemoteError) Error() string { return "control plane: " + string(e) }

// Conn is the broker's end of the control channel: request/response calls plus pushes.
type Conn struct {
	ws      *websocket.Conn
	mu      sync.Mutex
	next    uint64
	pending map[uint64]chan Message
	err     error
	// Pushes delivers Control Plane pushes (ID 0) until the channel closes, then is closed.
	// A push that finds it full is dropped.
	Pushes chan Message
}

// NewConn starts reading ws.
func NewConn(ctx context.Context, ws *websocket.Conn) *Conn {
	c := &Conn{ws: ws, pending: map[uint64]chan Message{}, Pushes: make(chan Message, 16)}
	go c.read(ctx)
	return c
}

func (c *Conn) read(ctx context.Context) {
	var err error
	defer func() {
		c.mu.Lock()
		c.err = errors.Join(ErrClosed, err)
		for id, ch := range c.pending {
			close(ch)
			delete(c.pending, id)
		}
		c.mu.Unlock()
		close(c.Pushes)
		c.ws.CloseNow()
	}()
	for {
		var data []byte
		if _, data, err = c.ws.Read(ctx); err != nil {
			return
		}
		var m Message
		if err = json.Unmarshal(data, &m); err != nil || m.V != 1 {
			err = errors.New("brokerproto: unsupported message")
			return
		}
		if m.ID == 0 {
			// A push never stalls the reader: results still reach pending calls. A dropped
			// push is a lost relay, which the Control Plane and CLI already handle.
			select {
			case c.Pushes <- m:
			default:
				log.Printf("[BROKER] push queue full; dropped a %q push", m.Type)
			}
			continue
		}
		c.mu.Lock()
		ch := c.pending[m.ID]
		delete(c.pending, m.ID)
		c.mu.Unlock()
		if ch != nil {
			ch <- m
		}
	}
}

// Call sends one request and decodes the result into out (which may be nil).
func (c *Conn) Call(ctx context.Context, typ string, req, out any) error {
	body, err := json.Marshal(req)
	if err != nil {
		return err
	}
	ch := make(chan Message, 1)
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return c.err
	}
	c.next++
	id := c.next
	c.pending[id] = ch
	c.mu.Unlock()
	b, _ := json.Marshal(Message{V: 1, Type: typ, ID: id, Body: body})
	if err := c.ws.Write(ctx, websocket.MessageText, b); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return err
	}
	select {
	case m, ok := <-ch:
		if !ok {
			return ErrClosed
		}
		if m.Error != "" {
			return RemoteError(m.Error)
		}
		if out == nil {
			return nil
		}
		return json.Unmarshal(m.Body, out)
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()
	}
}

// Close closes the channel.
func (c *Conn) Close() error { return c.ws.Close(websocket.StatusNormalClosure, "") }
