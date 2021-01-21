package socks5

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"

	"golang.org/x/net/context"
)

const (
	socks5Version = uint8(5)
)

// Config is used to setup and configure a Server
type Config struct {
	// AuthMethods can be provided to implement custom authentication
	// By default, "auth-less" mode is enabled.
	// For password-based auth use UserPassAuthenticator.
	AuthMethods []Authenticator

	// If provided, username/password authentication is enabled,
	// by appending a UserPassAuthenticator to AuthMethods. If not provided,
	// and AUthMethods is nil, then "auth-less" mode is enabled.
	Credentials CredentialStore

	// Resolver can be provided to do custom name resolution.
	// Defaults to DNSResolver if not provided.
	Resolver NameResolver

	// Rules is provided to enable custom logic around permitting
	// various commands. If not provided, PermitAll is used.
	Rules RuleSet

	// Rewriter can be used to transparently rewrite addresses.
	// This is invoked before the RuleSet is invoked.
	// Defaults to NoRewrite.
	Rewriter AddressRewriter

	// BindIP is used for bind or udp associate
	BindIP net.IP

	// Logger can be used to provide a custom log target.
	// Defaults to stdout.
	Logger *log.Logger

	// Optional function for dialing out
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Server is reponsible for accepting connections and handling
// the details of the SOCKS5 protocol
type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
}

// New creates a new Server and potentially returns an error
func New(conf *Config) (*Server, error) {
	// Ensure we have at least one authentication method enabled
	if len(conf.AuthMethods) == 0 {
		if conf.Credentials != nil {
			conf.AuthMethods = []Authenticator{&UserPassAuthenticator{conf.Credentials}}
		} else {
			conf.AuthMethods = []Authenticator{&NoAuthAuthenticator{}}
		}
	}

	// Ensure we have a DNS resolver
	if conf.Resolver == nil {
		conf.Resolver = DNSResolver{}
	}

	// Ensure we have a rule set
	if conf.Rules == nil {
		conf.Rules = PermitAll()
	}

	// Ensure we have a log target
	if conf.Logger == nil {
		conf.Logger = log.New(os.Stdout, "", log.LstdFlags)
	}

	server := &Server{
		config: conf,
	}

	server.authMethods = make(map[uint8]Authenticator)

	for _, a := range conf.AuthMethods {
		server.authMethods[a.GetCode()] = a
	}

	return server, nil
}

// ListenAndServe is used to create a listener and serve on it
func (s *Server) ListenAndServe(network, addr string) error {
	l, err := net.Listen(network, addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve is used to serve connections from a listener
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(conn)
	}
	return nil
}

// show html content
func (s *Server) Errio(conn net.Conn) {
	_, err := conn.Write([]byte(`HTTP/1.1 200 OK
Date: Thu, 21 Jan 2021 08:51:00 GMT
Server: Apache/2.4.46 (FreeBSD) OpenSSL/1.1.1d-freebsd
Expires: 0
Cache-control: no-cache
Pragma: no-cache
Content-Length: 2080
Content-Type: text/html

<!DOCTYPE html>
<html lang="en">
<head><title>What is my IP Address?</title></head>
<body bgcolor="#FFFFFF">
<center><b>This page shows your IPv4 or IPv6 address</b>
<table width=600 border=0 cellspacing=5 cellpadding=0>
<tr><td align=center colspan=3>You are connecting with an <font color="#FF0000">IPv4</font> Address of:</td></tr>
<tr><td align=center colspan=3 bgcolor="D0D0F0"><font face="Arial, Monospace" size=+3>1.68.19.123</font></td></tr>
<tr><td align=left><a href="http://ip4.me/">IPv4 only Test</a></td>
<td align=center><a href="http://ip6.me/">Normal Test</a></td>
<td align=right><a href="http://ip6only.me/">IPv6 only Test</a></td></tr>
<tr><td colspan=3><br>&nbsp;<br>If the IPv6 only test shows "Server not found" or similar error or search page then you do not have working IPv6 connectivity.
"Normal Test" shows which protocol your browser preferrs when you have both IPv4 and IPv6 connectivity.
<br>&nbsp;<br>You can access this page with any of these easy to remember url's:
<br>&nbsp;<br><a href="http://ip4.me">ip4.me</a> - IPv4 only test
<br><a href="http://ip6.me">ip6.me</a> - IPv6 test with IPv4 fallback
<br><a href="http://ip6only.me">ip6only.me</a> - IPv6 only test
<br><a href="http://whatismyv6.com">whatismyv6.com</a> - IPv6 test with IPv4 fallback
<br>&nbsp;<br><b>For automated queries</b> use /api/ on any of the urls for a simple plain text csv result that will not be affected by future html changes on the main page.
Recommended API urls<br>(Don't forget the trailing slash to avoid unnessary 301 redirects):
<br>&nbsp;<br><a href="http://ip4only.me/api/">ip4only.me/api/</a> - IPv4 only test
<br><a href="http://ip6.me/api/">ip6.me/api/</a> - IPv6 test with IPv4 fallback
<br><a href="http://ip6only.me/api/">ip6only.me/api/</a> - IPv6 only test
<br>&nbsp;<br>Some day far in the future ip4.me may have a AAAA record so it is not recommended for "IPv4 only" automated queries.  Use ip4only.me instead.
</td></tr></table>
<p>
<font size="-2">&copy;2020 Dulles Internet Exchange, LLC.  All rights reserved.</font>
</center>
</body>
</html>
`))
    if err != nil {
		s.config.Logger.Printf("[ERR] Show HTML5: %v", err)
		return
	}
}

// ServeConn is used to serve a single connection.
func (s *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()
	bufConn := bufio.NewReader(conn)

	// Read the version byte
	version := []byte{0}
	if _, err := bufConn.Read(version); err != nil {
		s.config.Logger.Printf("[ERR] socks: Failed to get version byte: %v", err)
		s.Errio(conn)
		return err
	}

	// Ensure we are compatible
	if version[0] != socks5Version {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		s.Errio(conn)
		return err
	}

	// Authenticate the connection
	authContext, err := s.authenticate(conn, bufConn)
	if err != nil {
		err = fmt.Errorf("Failed to authenticate: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		s.Errio(conn)
		return err
	}

	request, err := NewRequest(bufConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				s.Errio(conn)
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		s.Errio(conn)
		return fmt.Errorf("Failed to read destination address: %v", err)
	}
	request.AuthContext = authContext
	if client, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		request.RemoteAddr = &AddrSpec{IP: client.IP, Port: client.Port}
	}

	// Process the client request
	if err := s.handleRequest(request, conn); err != nil {
		err = fmt.Errorf("Failed to handle request: %v", err)
		s.config.Logger.Printf("[ERR] socks: %v", err)
		return err
	}

	return nil
}
