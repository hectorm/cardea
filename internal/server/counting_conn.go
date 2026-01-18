package server

import (
	"net"
	"sync/atomic"
)

type countingConn struct {
	net.Conn
	bytesRead    *atomic.Uint64
	bytesWritten *atomic.Uint64
}

func (c *countingConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if n > 0 {
		c.bytesRead.Add(uint64(n))
	}
	return
}

func (c *countingConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if n > 0 {
		c.bytesWritten.Add(uint64(n))
	}
	return
}
