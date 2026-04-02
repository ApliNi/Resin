package proxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Resinat/Resin/internal/node"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type noopOutbound struct {
	adapter.Outbound
}

func (n *noopOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errors.New("not used in transport-pool tests")
}

func (n *noopOutbound) Tag() string  { return "noop" }
func (n *noopOutbound) Type() string { return "noop" }

func TestOutboundTransportPool_ReusesByNodeHash(t *testing.T) {
	pool := newOutboundTransportPool()
	hash := node.Hash{1}

	t1 := pool.Get(hash, &noopOutbound{}, nil)
	t2 := pool.Get(hash, &noopOutbound{}, nil)

	if t1 != t2 {
		t.Fatal("expected same transport instance for identical node hash")
	}
}

func TestOutboundTransportPool_SplitsByNodeHash(t *testing.T) {
	pool := newOutboundTransportPool()
	ob := &noopOutbound{}
	hash1 := node.Hash{1}
	hash2 := node.Hash{2}

	base := pool.Get(hash1, ob, nil)
	byNodeHash := pool.Get(hash2, ob, nil)
	if base == byNodeHash {
		t.Fatal("expected different transport for different node hash")
	}
}

func TestOutboundTransportPool_UsesKeepAliveTransport(t *testing.T) {
	pool := newOutboundTransportPool()
	ob := &noopOutbound{}
	hash := node.Hash{1}

	transport := pool.Get(hash, ob, nil)
	if transport.DisableKeepAlives {
		t.Fatal("expected keep-alive enabled transport")
	}
}

func TestOutboundTransportPool_EvictRemovesNodeTransport(t *testing.T) {
	pool := newOutboundTransportPool()
	hash := node.Hash{1}
	ob := &noopOutbound{}

	t1 := pool.Get(hash, ob, nil)
	pool.Evict(hash)
	t2 := pool.Get(hash, ob, nil)

	if t1 == t2 {
		t.Fatal("expected a new transport after evict")
	}
}

func TestOutboundTransportPool_AppliesConfiguredLimits(t *testing.T) {
	pool := newOutboundTransportPoolWithConfig(OutboundTransportConfig{
		MaxIdleConns:        9,
		MaxIdleConnsPerHost: 3,
		IdleConnTimeout:     12 * time.Second,
		BypassList:          []string{"localhost"},
	})
	ob := &noopOutbound{}
	hash := node.Hash{1}

	transport := pool.Get(hash, ob, nil)
	if transport.MaxIdleConns != 9 {
		t.Fatalf("MaxIdleConns: got %d, want %d", transport.MaxIdleConns, 9)
	}
	if transport.MaxIdleConnsPerHost != 3 {
		t.Fatalf("MaxIdleConnsPerHost: got %d, want %d", transport.MaxIdleConnsPerHost, 3)
	}
	if transport.IdleConnTimeout != 12*time.Second {
		t.Fatalf("IdleConnTimeout: got %s, want %s", transport.IdleConnTimeout, 12*time.Second)
	}
}

func TestOutboundTransportPool_DirectDialBypassMatch(t *testing.T) {
	calledDirect := 0
	calledOutbound := 0
	pool := newOutboundTransportPoolWithConfig(OutboundTransportConfig{
		BypassList: []string{"localhost", "127.*"},
		directDialContext: func(context.Context, string, string) (net.Conn, error) {
			calledDirect++
			return nil, errors.New("direct dial sentinel")
		},
	})
	hash := node.Hash{1}
	transport := pool.Get(hash, &trackingOutbound{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		calledOutbound++
		return nil, errors.New("outbound dial sentinel")
	}}, nil)
	_, err := transport.DialContext(context.Background(), "tcp", "localhost:443")
	if err == nil || err.Error() != "direct dial sentinel" {
		t.Fatalf("DialContext() error = %v, want direct dial sentinel", err)
	}
	if calledDirect != 1 {
		t.Fatalf("calledDirect = %d, want 1", calledDirect)
	}
	if calledOutbound != 0 {
		t.Fatalf("calledOutbound = %d, want 0", calledOutbound)
	}
}

func TestOutboundTransportPool_UsesOutboundWhenBypassMisses(t *testing.T) {
	calledDirect := 0
	calledOutbound := 0
	pool := newOutboundTransportPoolWithConfig(OutboundTransportConfig{
		BypassList: []string{"localhost"},
		directDialContext: func(context.Context, string, string) (net.Conn, error) {
			calledDirect++
			return nil, errors.New("direct dial sentinel")
		},
	})
	hash := node.Hash{1}
	transport := pool.Get(hash, &trackingOutbound{dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
		calledOutbound++
		return nil, errors.New("outbound dial sentinel")
	}}, nil)
	_, err := transport.DialContext(context.Background(), "tcp", "example.com:443")
	if err == nil || err.Error() != "outbound dial sentinel" {
		t.Fatalf("DialContext() error = %v, want outbound dial sentinel", err)
	}
	if calledDirect != 0 {
		t.Fatalf("calledDirect = %d, want 0", calledDirect)
	}
	if calledOutbound != 1 {
		t.Fatalf("calledOutbound = %d, want 1", calledOutbound)
	}
}

func TestOutboundTransportPool_CloseAllClearsEntries(t *testing.T) {
	pool := newOutboundTransportPool()
	ob := &noopOutbound{}

	hashA := node.Hash{1}
	hashB := node.Hash{2}
	t1 := pool.Get(hashA, ob, nil)
	_ = pool.Get(hashB, ob, nil)

	pool.CloseAll()

	t2 := pool.Get(hashA, ob, nil)
	if t1 == t2 {
		t.Fatal("expected a new transport after CloseAll")
	}
}

type trackingOutbound struct {
	adapter.Outbound
	dial func(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
}

func (o *trackingOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.dial(ctx, network, destination)
}

func (o *trackingOutbound) Tag() string  { return "tracking" }
func (o *trackingOutbound) Type() string { return "tracking" }
