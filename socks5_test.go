package socks5

import (
	"bytes"
	"code.google.com/p/go.net/proxy"
	// "encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestSOCKS5_Connect(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Fatalf("err: %v", err)
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Fatalf("bad: %v", buf)
		}
		conn.Write([]byte("pong"))
	}()
	// lAddr := l.Addr().(*net.TCPAddr)

	// Create a socks server
	creds := StaticCredentials{
		"foo": "bar",
	}
	cator := UserPassAuthenticator{Credentials: creds}
	conf := &Config{
		AuthMethods: []Authenticator{cator, NoAuthAuthenticator{}},
	}
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Start listening
	go func() {
		if err := serv.ListenAndServe("tcp", "127.0.0.1:12365"); err != nil {
			t.Fatalf("err: %v", err)
		}
	}()
	time.Sleep(10 * time.Millisecond)

	auth := &proxy.Auth{"foo", "bar"}
	dialer, e := proxy.SOCKS5("tcp", "127.0.0.1:12365", auth, proxy.Direct)
	if e != nil {
		t.Error(e)
	}

	conn, e := dialer.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Error(e)
	}

	conn.Write([]byte("ping"))

	out := make([]byte, 4)

	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(conn, out); err != nil {
		t.Fatalf("err: %v", err)
	}

	if !bytes.Equal(out, []byte("pong")) {
		t.Fatalf("bad: %v", out)
	}
}
