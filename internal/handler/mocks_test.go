package handler_test

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/davidsbond/dns/internal/handler"
)

type (
	MockDNSResponseWriter struct {
		dns.ResponseWriter
		message *dns.Msg
	}
)

func (m *MockDNSResponseWriter) Write(b []byte) (int, error) {
	m.message = new(dns.Msg)
	if err := m.message.Unpack(b); err != nil {
		return 0, err
	}

	return len(b), nil
}

func (m *MockDNSResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.message = msg
	return nil
}

func (m *MockDNSResponseWriter) RemoteAddr() net.Addr {
	addr := &net.IPAddr{}

	return addr
}

type (
	MockDNSClient struct {
		handler.DNSClient
		response *dns.Msg
		rtt      time.Duration
		err      error
	}
)

func (m *MockDNSClient) ExchangeContext(_ context.Context, _ *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
	return m.response, m.rtt, m.err
}
