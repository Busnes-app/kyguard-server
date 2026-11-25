package broker

import (
	"context"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// ControlPlane is what the broker asks of the Control Plane. It authorizes nothing; the
// broker checks everything it receives.
type ControlPlane interface {
	Sync(ctx context.Context, manifestsAfter int) (*brokerproto.SyncReply, error)
	SyncAccount(ctx context.Context, account pqcrypto.UUID, afterVersion pqcrypto.Counter) (*brokerproto.AccountState, error)
	Reserve(ctx context.Context, account, op pqcrypto.UUID, reported pqcrypto.Counter) (pqcrypto.Counter, error)
	StoreEnvelope(ctx context.Context, op pqcrypto.UUID, envelope []byte) error
	Intent(ctx context.Context, intent []byte) error
	Receipts(ctx context.Context, op, account pqcrypto.UUID, receipts []pqcrypto.B64) error
	Status(ctx context.Context, s brokerproto.StatusRequest) error
}

// channelCP is the ControlPlane over the control channel.
type channelCP struct{ c *brokerproto.Conn }

// NewChannelCP wraps an open channel.
func NewChannelCP(c *brokerproto.Conn) ControlPlane { return channelCP{c} }

func (c channelCP) Sync(ctx context.Context, manifestsAfter int) (*brokerproto.SyncReply, error) {
	var r brokerproto.SyncReply
	return &r, c.c.Call(ctx, brokerproto.MsgSync, brokerproto.SyncRequest{ManifestsAfter: manifestsAfter}, &r)
}

func (c channelCP) SyncAccount(ctx context.Context, account pqcrypto.UUID, afterVersion pqcrypto.Counter) (*brokerproto.AccountState, error) {
	var r brokerproto.AccountState
	return &r, c.c.Call(ctx, brokerproto.MsgSyncAccount, brokerproto.SyncAccountRequest{AccountID: account, AfterVersion: afterVersion}, &r)
}

func (c channelCP) Reserve(ctx context.Context, account, op pqcrypto.UUID, reported pqcrypto.Counter) (pqcrypto.Counter, error) {
	var r brokerproto.ReserveReply
	err := c.c.Call(ctx, brokerproto.MsgReserve, brokerproto.ReserveRequest{AccountID: account, OperationID: op, Reported: reported}, &r)
	return r.SecretVersion, err
}

func (c channelCP) StoreEnvelope(ctx context.Context, op pqcrypto.UUID, envelope []byte) error {
	return c.c.Call(ctx, brokerproto.MsgEnvelope, brokerproto.EnvelopeRequest{OperationID: op, Envelope: envelope}, nil)
}

func (c channelCP) Intent(ctx context.Context, intent []byte) error {
	return c.c.Call(ctx, brokerproto.MsgIntent, brokerproto.IntentRequest{Intent: intent}, nil)
}

func (c channelCP) Receipts(ctx context.Context, op, account pqcrypto.UUID, receipts []pqcrypto.B64) error {
	return c.c.Call(ctx, brokerproto.MsgReceipts, brokerproto.ReceiptsRequest{OperationID: op, AccountID: account, Receipts: receipts}, nil)
}

func (c channelCP) Status(ctx context.Context, s brokerproto.StatusRequest) error {
	return c.c.Call(ctx, brokerproto.MsgStatus, s, nil)
}
