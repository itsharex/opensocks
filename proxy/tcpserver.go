package proxy

import (
	"log"
	"net"

	"github.com/net-byte/opensocks/common/enum"
	"github.com/net-byte/opensocks/common/pool"
	"github.com/net-byte/opensocks/config"
)

// The tcp server struct
type TCPServer struct {
	Config   config.Config
	Tproxy   *TCPProxy
	Uproxy   *UDPProxy
	UDPConn  *net.UDPConn
	Listener net.Listener
}

// Start starts the tcp server
func (t *TCPServer) Start() {
	log.Printf("opensocks [tcp] client started on %s", t.Config.LocalAddr)
	var err error
	t.Listener, err = net.Listen("tcp", t.Config.LocalAddr)
	if err != nil {
		log.Panicf("[tcp] failed to listen tcp %v", err)
	}
	for {
		tcpConn, err := t.Listener.Accept()
		if err != nil {
			break
		}
		go t.handler(tcpConn, t.UDPConn)
	}
}

// handler handles the tcp connection
func (t *TCPServer) handler(tcpConn net.Conn, udpConn *net.UDPConn) {
	if !t.checkVersion(tcpConn) {
		tcpConn.Close()
		return
	}
	//no auth
	respNoAuth(tcpConn)
	t.cmd(tcpConn, udpConn)
}

// checkVersion checks the version
func (t *TCPServer) checkVersion(tcpConn net.Conn) bool {
	buf := pool.BytePool.Get()
	defer pool.BytePool.Put(buf)
	n, err := tcpConn.Read(buf[0:])
	if err != nil || n == 0 {
		return false
	}
	b := buf[0:n]
	if b[0] != enum.Socks5Version {
		resp(tcpConn, enum.ConnectionRefused)
		return false
	}
	return true
}

// cmd handles the command
func (t *TCPServer) cmd(tcpConn net.Conn, udpConn *net.UDPConn) {
	buf := pool.BytePool.Get()
	defer pool.BytePool.Put(buf)
	n, err := tcpConn.Read(buf[0:])
	if err != nil || n == 0 {
		return
	}
	b := buf[0:n]
	switch b[1] {
	case enum.ConnectCommand:
		t.Tproxy.Proxy(tcpConn, b)
		return
	case enum.AssociateCommand:
		t.Uproxy.Proxy(tcpConn, udpConn)
		return
	case enum.BindCommand:
		resp(tcpConn, enum.CommandNotSupported)
		return
	default:
		resp(tcpConn, enum.CommandNotSupported)
		return
	}
}
