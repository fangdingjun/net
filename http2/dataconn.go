package http2

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

/*
client data connection to the server,
return this struct when call Transport.Connect method
*/
type ClientDataConn struct {
	cs  *clientStream
	cc  *ClientConn
	Res *http.Response
}

/*
server data connection to the client,
return this struct when call the Hijick() method on responseWriter
*/
type ServerDataConn struct {
	rwr *responseWriter
}

/* check interface implement */
var _ io.ReadWriteCloser = &ClientDataConn{}
var _ net.Conn = &ServerDataConn{}
var _ http.Hijacker = &responseWriter{}

func (sdc *ServerDataConn) Read(b []byte) (int, error) {
	if sdc.rwr.rws == nil || sdc.rwr.rws.stream.gotReset {
		return 0, errors.New("stream closed")
	}
	return sdc.rwr.rws.body.Read(b)
}

func (sdc *ServerDataConn) Write(p []byte) (int, error) {
	if sdc.rwr.rws == nil || sdc.rwr.rws.stream.sentReset {
		return 0, errors.New("stream closed")
	}
	return sdc.rwr.rws.writeChunk(p)
}

func (sdc *ServerDataConn) Close() error {
	/* responseWriter.handlerDone() */
	rws := sdc.rwr.rws
	if rws == nil {
		panic("sdc handlerDone called twice")
	}
	rws.handlerDone = true
	sdc.rwr.Flush()
	sdc.rwr.rws = nil
	responseWriterStatePool.Put(rws)
	return nil
}

func (sdc *ServerDataConn) LocalAddr() net.Addr {
	return sdc.rwr.rws.conn.conn.LocalAddr()
}

func (sdc *ServerDataConn) RemoteAddr() net.Addr {
	return sdc.rwr.rws.conn.conn.RemoteAddr()
}

func (sdc *ServerDataConn) SetDeadline(time.Time) error {
	return nil
}

func (sdc *ServerDataConn) SetReadDeadline(time.Time) error {
	return nil
}

func (sdc *ServerDataConn) SetWriteDeadline(time.Time) error {
	return nil
}

/*
   when req.Method is CONNECT, call this to
   send the CONNECT method to server,
   return a data connection

*/
func (t *Transport) Connect(req *http.Request) (*ClientDataConn, error) {
	//var host, port string
	var err error

	addr := t.authorityAddr(req)
	cc, err := t.connPool().GetClientConn(req, addr)
	if err != nil {
		return nil, err
	}
	return cc.connect(req)
}

func (cc *ClientConn) connect(req *http.Request) (*ClientDataConn, error) {
	cc.mu.Lock()

	if cc.closed {
		cc.mu.Unlock()
		return nil, errClientConnClosed
	}

	cs := cc.newStream()
	hasBody := true // CONNECT always has the body

	// we send: HEADERS[+CONTINUATION] + (DATA?)
	hdrs := cc.encodeHeaders(req)
	first := true

	cc.wmu.Lock()
	frameSize := int(cc.maxFrameSize)
	for len(hdrs) > 0 && cc.werr == nil {
		chunk := hdrs
		if len(chunk) > frameSize {
			chunk = chunk[:frameSize]
		}
		hdrs = hdrs[len(chunk):]
		endHeaders := len(hdrs) == 0
		if first {
			cc.fr.WriteHeaders(HeadersFrameParam{
				StreamID:      cs.ID,
				BlockFragment: chunk,
				EndStream:     !hasBody,
				EndHeaders:    endHeaders,
			})
			first = false
		} else {
			cc.fr.WriteContinuation(cs.ID, endHeaders, chunk)
		}
	}
	cc.bw.Flush()
	werr := cc.werr
	cc.wmu.Unlock()
	cc.mu.Unlock()

	if werr != nil {
		return nil, werr
	}

	var re resAndError

	select {
	case re = <-cs.resc:
		if re.err != nil {
			return nil, re.err
		}
	case <-time.After(3 * time.Second):
		// request time out
		// close the connection
		cc.tconn.Close()
		log.Print("cc.connect: request timed out, may be connection hang")
		return nil, errors.New("request time out")
	}

	res := re.res
	res.Request = req
	res.TLS = cc.tlsState

	return &ClientDataConn{
		cc:  cc,
		cs:  cs,
		Res: res,
	}, nil
}

func (dc *ClientDataConn) Read(b []byte) (int, error) {
	if dc.cs.resetErr != nil {
		return 0, dc.cs.resetErr
	}

	if dc.cs.bufPipe.err != nil {
		return 0, dc.cs.bufPipe.err
	}

	return dc.Res.Body.Read(b)
}

func (dc *ClientDataConn) Write(b []byte) (int, error) {
	if dc.cs.resetErr != nil {
		return 0, dc.cs.resetErr
	}

	cs := dc.cs
	cc := dc.cc
	endStream := false // whether we sent the final DATA frame w/ END_STREAM

	var err error = nil

	toWrite := b
	for len(toWrite) > 0 && err == nil {
		var allowed int32
		allowed, err = cs.awaitFlowControl(int32(len(toWrite)))
		if err != nil {
			return 0, err
		}

		cc.wmu.Lock()
		data := toWrite[:allowed]
		toWrite = toWrite[allowed:]
		err = cc.fr.WriteData(cs.ID, endStream, data)
		cc.wmu.Unlock()
	}
	if err != nil {
		return 0, err
	}

	cc.wmu.Lock()
	if ferr := cc.bw.Flush(); ferr != nil && err == nil {
		err = ferr
	}
	cc.wmu.Unlock()

	return len(b), err
}

func (dc *ClientDataConn) Close() error {
	cs := dc.cs
	cc := dc.cc

	endStream := true // set the end stream flag

	cc.wmu.Lock()
	err := cc.fr.WriteData(cs.ID, endStream, nil)
	if err != nil {
		cc.wmu.Unlock()
		return err
	}
	err = cc.bw.Flush()
	cc.wmu.Unlock()

	/* close http.Response body */
	dc.Res.Body.Close()

	return err
}

/*
implement http.Hijacker interface,
return the data connection to the client
*/
func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.rws.stream.hijacked = true
	c := &ServerDataConn{w}
	rw := bufio.NewReadWriter(
		bufio.NewReader(c),
		bufio.NewWriter(c),
	)
	return c, rw, nil
}
