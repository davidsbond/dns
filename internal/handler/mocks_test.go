package handler_test

import (
	"net"

	"github.com/miekg/dns"
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
