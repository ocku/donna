// Independent Go DNS clients and connection lifecycle probes; standard library only.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

const timeout = 3 * time.Second

var host = "172.29.53.10"
var tlsConfig *tls.Config

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func query(bits, id uint16) []byte {
	wire := make([]byte, 12)
	binary.BigEndian.PutUint16(wire, id)
	binary.BigEndian.PutUint16(wire[2:], bits&0x130)
	binary.BigEndian.PutUint16(wire[4:], 1)
	binary.BigEndian.PutUint16(wire[10:], 1)
	for _, label := range []string{"WwW", "ExAmPlE", "TeSt"} {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	wire = append(wire, 0, 0, 1, 0, 1)
	opt := []byte{0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(opt[7:], bits&0x8000)
	return append(wire, opt...)
}

func nameEnd(wire []byte, offset int) int {
	for labels := 0; labels < 128; labels++ {
		require(offset < len(wire), "truncated name")
		length := int(wire[offset])
		offset++
		if length == 0 {
			return offset
		}
		if length&0xc0 == 0xc0 {
			require(offset < len(wire), "truncated pointer")
			return offset + 1
		}
		require(length < 64, "invalid label")
		offset += length
		require(offset <= len(wire), "truncated label")
	}
	panic("too many labels")
}

func validate(wire, request []byte) {
	require(len(wire) >= 12, "short response")
	require(binary.BigEndian.Uint16(wire) == binary.BigEndian.Uint16(request), "response ID mismatch")
	flags := binary.BigEndian.Uint16(wire[2:])
	require(flags&0x868f == 0x8400, "QR/AA or TC/RA/RCODE mismatch")
	require(flags&0x30 == 0, "authoritative AD/CD not cleared")
	require(flags&0x100 == binary.BigEndian.Uint16(request[2:])&0x100, "RD not copied")
	require(binary.BigEndian.Uint16(wire[4:]) == 1, "question count mismatch")
	cursor := nameEnd(wire, 12) + 4
	require(cursor <= len(wire) && bytes.Equal(wire[12:cursor], request[12:cursor]), "question case mismatch")
	found := false
	optCount := 0
	for _, countOffset := range []int{6, 8, 10} {
		for remaining := int(binary.BigEndian.Uint16(wire[countOffset:])); remaining > 0; remaining-- {
			cursor = nameEnd(wire, cursor)
			require(cursor+10 <= len(wire), "truncated record")
			kind := binary.BigEndian.Uint16(wire[cursor:])
			length := int(binary.BigEndian.Uint16(wire[cursor+8:]))
			if kind == 41 {
				require(countOffset == 10, "OPT belongs in the additional section")
				require(binary.BigEndian.Uint16(wire[cursor+6:])&0x8000 ==
					binary.BigEndian.Uint16(request[len(request)-4:])&0x8000, "DO not copied")
				optCount++
			}
			cursor += 10
			require(cursor+length <= len(wire), "truncated rdata")
			if countOffset == 6 && kind == 1 && bytes.Equal(wire[cursor:cursor+length], []byte{192, 0, 2, 80}) {
				found = true
			}
			cursor += length
		}
	}
	require(cursor == len(wire), "trailing DNS response data")
	require(optCount == 1, "expected exactly one OPT")
	require(found, "missing expected IPv4 address")
}

func validateAnswers(answers, requests [][]byte) {
	require(len(answers) == len(requests), "response count mismatch")
	pending := make(map[uint16][]byte)
	for _, request := range requests {
		id := binary.BigEndian.Uint16(request)
		require(pending[id] == nil, "duplicate in-flight ID")
		pending[id] = request
	}
	for _, answer := range answers {
		require(len(answer) >= 2, "short response ID")
		id := binary.BigEndian.Uint16(answer)
		request, found := pending[id]
		require(found, "unknown or duplicate response ID")
		validate(answer, request)
		delete(pending, id)
	}
	require(len(pending) == 0, "unanswered query")
}

func udp(request []byte) []byte {
	connection, err := net.DialTimeout("udp", net.JoinHostPort(host, "5300"), timeout)
	check(err)
	defer connection.Close()
	check(connection.SetDeadline(time.Now().Add(timeout)))
	_, err = connection.Write(request)
	check(err)
	buffer := make([]byte, 65535)
	length, err := connection.Read(buffer)
	check(err)
	return buffer[:length]
}

func frame(request []byte) []byte {
	prefix := make([]byte, 2)
	binary.BigEndian.PutUint16(prefix, uint16(len(request)))
	return append(prefix, request...)
}

func stream(requests [][]byte, encrypted, fragments, halfClose bool) [][]byte {
	var connection net.Conn
	var err error
	dialer := &net.Dialer{Timeout: timeout}
	if encrypted {
		dotConfig := tlsConfig.Clone()
		dotConfig.NextProtos = []string{"dot"}
		connection, err = tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, "8530"), dotConfig)
	} else {
		connection, err = dialer.Dial("tcp", net.JoinHostPort(host, "5300"))
	}
	check(err)
	defer connection.Close()
	check(connection.SetDeadline(time.Now().Add(timeout)))
	for _, request := range requests {
		data := frame(request)
		if fragments {
			for _, value := range data {
				_, err = connection.Write([]byte{value})
				check(err)
			}
		} else {
			_, err = connection.Write(data)
			check(err)
		}
	}
	if halfClose {
		check(connection.(*net.TCPConn).CloseWrite())
	}
	answers := make([][]byte, 0, len(requests))
	for range requests {
		prefix := make([]byte, 2)
		_, err = io.ReadFull(connection, prefix)
		check(err)
		answer := make([]byte, binary.BigEndian.Uint16(prefix))
		_, err = io.ReadFull(connection, answer)
		check(err)
		answers = append(answers, answer)
	}
	return answers
}

func doh(request []byte, method string) []byte {
	transport := &http.Transport{TLSClientConfig: tlsConfig, ForceAttemptHTTP2: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout}
	url := "https://" + net.JoinHostPort(host, "8443") + "/dns-query"
	var body io.Reader
	if method == "GET" {
		url += "?dns=" + base64.RawURLEncoding.EncodeToString(request)
	} else {
		body = bytes.NewReader(request)
	}
	req, err := http.NewRequest(method, url, body)
	check(err)
	req.Header.Set("Content-Type", "application/dns-message")
	response, err := client.Do(req)
	check(err)
	defer response.Body.Close()
	require(response.StatusCode == 200, fmt.Sprint("HTTP status ", response.StatusCode))
	require(response.ProtoMajor == 2, "HTTP/2 was not negotiated")
	wire, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	check(err)
	return wire
}

func aborts() {
	for _, data := range [][]byte{{}, {0}, {255, 255, 0}, {0, 0}} {
		connection, err := net.DialTimeout("tcp", net.JoinHostPort(host, "5300"), timeout)
		check(err)
		check(connection.SetDeadline(time.Now().Add(timeout)))
		_, err = connection.Write(data)
		check(err)
		check(connection.Close())
		request := query(0x100, 47000)
		validate(udp(request), request)
	}
}

func main() {
	if value := os.Getenv("DONNA_HOST"); value != "" {
		host = value
	}
	certificate, err := os.ReadFile("/certs/cert.pem")
	check(err)
	roots := x509.NewCertPool()
	require(roots.AppendCertsFromPEM(certificate), "invalid fixture certificate")
	tlsConfig = &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13}
	checks := 0
	for mask := uint16(0); mask < 16; mask++ {
		bits := (mask&1)<<8 | (mask&2)<<3 | (mask&4)<<3 | (mask&8)<<12
		request := query(bits, 45000+mask)
		validate(udp(request), request)
		validate(stream([][]byte{request}, false, false, false)[0], request)
		validate(stream([][]byte{request}, true, false, false)[0], request)
		validate(doh(request, "GET"), request)
		validate(doh(request, "POST"), request)
		checks += 5
	}
	pipeline := make([][]byte, 12)
	for index := range pipeline {
		pipeline[index] = query(0x100, uint16(46000+index))
	}
	for _, options := range [][3]bool{{}, {false, true, false}, {false, false, true}, {true, true, false}} {
		// RFC 7766 section 7 permits responses in a different order.
		answers := stream(pipeline, options[0], options[1], options[2])
		validateAnswers(answers, pipeline)
		checks += len(answers)
	}
	aborts()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, network, net.JoinHostPort(host, "5300"))
	}}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addresses, err := resolver.LookupHost(ctx, "www.example.test.")
	check(err)
	require(len(addresses) == 2, fmt.Sprint("Go resolver addresses: ", addresses))
	addressSet := map[string]bool{}
	for _, address := range addresses {
		addressSet[address] = true
	}
	require(addressSet["192.0.2.80"] && addressSet["2001:db8::80"], "Go resolver returned unexpected addresses")
	records, err := resolver.LookupTXT(ctx, "large.example.test.")
	check(err)
	require(len(records) == 10, "Go resolver TCP fallback incomplete")
	fmt.Printf("PASS Go %d raw flag/stream checks, early aborts, standard DNS and TCP fallback\n", checks)
}
