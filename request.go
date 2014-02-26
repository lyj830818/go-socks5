package socks5

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

const (
	connectCommand   = uint8(1)
	bindCommand      = uint8(2)
	associateCommand = uint8(3)
	ipv4Address      = uint8(1)
	fqdnAddress      = uint8(3)
	ipv6Address      = uint8(4)
)

const (
	successReply uint8 = iota
	serverFailure
	ruleFailure
	networkUnreachable
	hostUnreachable
	connectionRefused
	ttlExpired
	commandNotSupported
	addrTypeNotSupported
)

var (
	unrecognizedAddrType = fmt.Errorf("Unrecognized address type")
)

// AddressRewriter is used to rewrite a destination transparently
type AddressRewriter interface {
	Rewrite(addr *AddrSpec) *AddrSpec
}

// AddrSpec is used to return the target AddrSpec
// which may be specified as IPv4, IPv6, or a FQDN
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

// type conn interface {
// 	Write([]byte) (int, error)
// 	RemoteAddr() net.Addr
// }

func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// handleRequest is used for request processing after authentication
func (s *Server) handleRequest(conn net.Conn) error {
	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(conn, header, 3); err != nil {
		return fmt.Errorf("Failed to get command version: %v", err)
	}

	// Ensure we are compatible
	if header[0] != socks5Version {
		return fmt.Errorf("Unsupported command version: %v", header[0])
	}

	// Read in the destination address
	dest, err := readAddrSpec(conn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}

	// Resolve the address if we have a FQDN
	if dest.FQDN != "" {
		addr, err := s.config.Resolver.Resolve(dest.FQDN)
		if err != nil {
			if err := sendReply(conn, hostUnreachable, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
			return fmt.Errorf("Failed to resolve destination '%v': %v", dest.FQDN, err)
		}
		dest.IP = addr
	}

	// Apply any address rewrites
	realDest := dest
	if s.config.Rewriter != nil {
		realDest = s.config.Rewriter.Rewrite(dest)
	}
	// Switch on the command
	switch header[1] {
	case connectCommand:
		return s.handleConnect(conn, dest, realDest)
	case bindCommand:
		return s.handleBind(conn, dest, realDest)
	case associateCommand:
		return s.handleAssociate(conn, dest, realDest)
	default:
		if err := sendReply(conn, commandNotSupported, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Unsupported command: %v", header[1])
	}
	return nil
}

// handleConnect is used to handle a connect command
func (s *Server) handleConnect(conn net.Conn, dest, realDest *AddrSpec) error {
	// Check if this is allowed
	client := conn.RemoteAddr().(*net.TCPAddr)
	if !s.config.Rules.AllowConnect(realDest.IP, realDest.Port, client.IP, client.Port) {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v blocked by rules", dest)
	}

	var target net.Conn
	var err error
	if s.config.Dialer != nil {
		target, err = s.config.Dialer.Dial("tcp", fmt.Sprintf("%s:%d", dest.IP.String(), dest.Port))
	} else {
		// Attempt to connect
		addr := net.TCPAddr{IP: realDest.IP, Port: realDest.Port}
		target, err = net.DialTCP("tcp", nil, &addr)
	}
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(conn, resp, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", dest, err)
	}
	defer target.Close()

	// Send success
	local := target.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(conn, successReply, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	return doProxy2(target, conn)
}

// handleBind is used to handle a connect command
func (s *Server) handleBind(conn net.Conn, dest, realDest *AddrSpec) error {
	// Check if this is allowed
	client := conn.RemoteAddr().(*net.TCPAddr)
	if !s.config.Rules.AllowBind(realDest.IP, realDest.Port, client.IP, client.Port) {
		if err := sendReply(conn, ruleFailure, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Bind to %v blocked by rules", dest)
	}

	// TODO: Support bind
	if err := sendReply(conn, commandNotSupported, nil); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}
	return nil
}

// handleAssociate is used to handle a connect command
func (s *Server) handleAssociate(conn net.Conn, dest, realDest *AddrSpec) error {
	// create a udp server
	udpAddr := &net.UDPAddr{IP: conn.LocalAddr().(*net.TCPAddr).IP, Port: 0}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Println(err)
		return err
	}
	defer udpConn.Close()

	local := udpConn.LocalAddr().(*net.UDPAddr)

	// Send success
	bind := AddrSpec{IP: local.IP.To4(), Port: local.Port}
	if err := sendReply(conn, successReply, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	b := make([]byte, 3)
	_, err = io.ReadAtLeast(udpConn, b, len(b))
	if err != nil {
		log.Println("io.ReadFull(udpConn, buf)", err)
		return err
	}
	dest, err = readAddrSpec(udpConn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				return fmt.Errorf("Failed to send reply: %v", err)
			}
		}
		return fmt.Errorf("Failed to read destination address: %v", err)
	}

	// Apply any address rewrites
	realDest = dest
	if s.config.Rewriter != nil {
		realDest = s.config.Rewriter.Rewrite(dest)
	}

	raddr := &net.UDPAddr{IP: realDest.IP, Port: realDest.Port}
	target, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(conn, resp, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", dest, err)
	}

	defer target.Close()

	return doProxy2(target, udpConn)
}

// readAddrSpec is used to read AddrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case fqdnAddress:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	default:
		return nil, unrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}

// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}

// proxy is used to suffle data from src to destination, and sends errors
// down a dedicated channel
func doProxy(name string, dst io.Writer, src io.Reader, errCh chan error) {
	// Copy
	p := make([]byte, 16)
	n, err := src.Read(p)
	if err != nil {
		log.Println(err)
		errCh <- err
		return
	}
	dst.Write(p)
	// n, err := io.Copy(dst, src)
	log.Println(name, n, err)
	time.Sleep(10 * time.Millisecond)
	// Send any errors
	errCh <- err
}

func doProxy2(l, r net.Conn) error {
	f := func(c1, c2 net.Conn) {
		io.Copy(c1, c2)
	}
	go func() {
		f(l, r)
	}()
	f(r, l)
	return nil
}

func readAddrSpec2(l net.PacketConn) (*AddrSpec, error) {
	d := &AddrSpec{}

	buf := []byte{0, 0, 0, 0}
	_, _, e := l.ReadFrom(buf)
	if e != nil {
		return nil, e
	}
	switch buf[4] {
	case ipv4Address:
		addrbuf := make([]byte, 4)
		_, _, e = l.ReadFrom(addrbuf)
		if e != nil {
			return nil, e
		}
		d.IP = net.IP(addrbuf)

	case ipv6Address:
		addrbuf := make([]byte, 16)
		_, _, e = l.ReadFrom(addrbuf)
		if e != nil {
			return nil, e
		}
		d.IP = net.IP(addrbuf)

	case fqdnAddress:
		_, _, e = l.ReadFrom(buf[:0])
		if e != nil {
			return nil, e
		}
		addrLen := int(buf[0])
		fqdn := make([]byte, addrLen)
		_, _, e = l.ReadFrom(fqdn)
		if e != nil {
			return nil, e
		}
		d.FQDN = string(fqdn)

	default:
		return nil, unrecognizedAddrType
	}
	// Read the port
	port := []byte{0, 0}
	_, _, e = l.ReadFrom(port)
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}
