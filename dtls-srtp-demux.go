package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

var dtlsFound bool

func searchDTLS(buf []byte) bool {
	// from https://www.rfcreader.com/#rfc5764
	//
	// The receiver looks at the first byte of the packet. If the value of this
	// byte is 0 or 1, then the packet is STUN. If the value is in between 128
	// and 191 (inclusive), then the packet is RTP (or RTCP, if both RTCP and
	// RTP are being multiplexed over the same destination port). If the value
	// is between 20 and 63 (inclusive), the packet is DTLS.

	if buf[0] > 19 && buf[0] < 64 {
		log.Println("DTLS packet found")
		return true
	}

	if buf[0] > 127 && buf[0] < 192 {
		log.Println("RTP packet found")
		return false
	}

	if buf[0] < 2 {
		log.Println("STUN packet found")
		return false
	}

	log.Println("xx")

	return false
}

func dtlsReplyLoop(targetConn *net.UDPConn, dtlsConn *net.UDPConn) {
	readBuf := make([]byte, 1500)

	for {
		read, _, err := dtlsConn.ReadFromUDP(readBuf)
		if err != nil {
			log.Fatal("dtlsReplyLoop: Could not read packet.")
			continue
		}

		if _, err := targetConn.Write(readBuf[0:read]); err != nil {
			log.Fatal("Could not forward packet.")
			continue
		}
	}
}

func udpProxyReplyLoop(targetConn *net.UDPConn, sourceConn *net.UDPConn, clientAddr *net.UDPAddr, dtlsConn *net.UDPConn) {
	readBuf := make([]byte, 1500)

	for {
		read, err := targetConn.Read(readBuf)
		if err != nil {
			log.Println("udpProxyReplyLoop: Could not read packet.")
			continue
		}

		// check/update global flag
		if !dtlsFound {
			dtlsFound = searchDTLS(readBuf)

			if dtlsFound {
				go dtlsReplyLoop(targetConn, dtlsConn)
			}
		}

		// check if this particular packet is DTLS
		currentPacketIsDTLS := searchDTLS(readBuf)

		if !currentPacketIsDTLS {
			sourceConn.WriteToUDP(readBuf[0:read], clientAddr)
			if err != nil {
				log.Fatal("Could not forward packet.")
				return
			}
		} else {
			// if there was a DTLS packet found in buffer sent by server,
			// send this data to the corresponding listener
			dtlsConn.Write(readBuf[0:read])
			if err != nil {
				log.Fatal("Could not forward packet.")
				return
			}
		}
	}
}

func udpProxyConnection(targetConn *net.UDPConn, sourceConn *net.UDPConn, dtlsConn *net.UDPConn) {
	readBuf := make([]byte, 1500)
	newClient := true

	for {
		var read int
		var from *net.UDPAddr
		var err error

		// waiting for our proxy client
		read, from, err = sourceConn.ReadFromUDP(readBuf)
		if err != nil {
			log.Fatal("udpProxyConnection: Could not read packet.")
			break
		}

		if newClient {
			newClient = false
			go udpProxyReplyLoop(targetConn, sourceConn, from, dtlsConn)
		}

		if _, err := targetConn.Write(readBuf[0:read]); err != nil {
			log.Fatal("Could not forward packet.")
			break
		}
	}
}

func udpProxyPrepare(remoteHost string, remotePort uint16, listenHost string, listenPort uint16, dtlsHost string, dtlsPort uint16) (*net.UDPConn, *net.UDPConn, *net.UDPConn, bool) {
	sourceAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", listenHost, listenPort))
	if err != nil {
		log.Fatal("Could not resolve source address: ", listenHost, listenPort)
		return nil, nil, nil, false
	}

	sourceConn, err := net.ListenUDP("udp", sourceAddr)
	if err != nil {
		log.Fatal("Could not listen on address:", sourceAddr)
		return nil, nil, nil, false
	}

	targetAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", remoteHost, remotePort))
	if err != nil {
		log.Fatal("Could not resolve target address:", remoteHost, remotePort)
		return nil, nil, nil, false
	}

	targetConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Fatal("Could not connect to target address:", targetAddr)
		return nil, nil, nil, false
	}

	dtlsAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", dtlsHost, dtlsPort))
	if err != nil {
		log.Fatal("Could not resolve target address:", dtlsHost, dtlsPort)
		return nil, nil, nil, false
	}

	dtlsConn, err := net.DialUDP("udp", nil, dtlsAddr)
	if err != nil {
		log.Fatal("Could not connect to target address:", targetAddr)
		return nil, nil, nil, false
	}

	return targetConn, sourceConn, dtlsConn, true
}

func main() {
	var remoteAddr *string = flag.String("H", "localhost", "remote server address")
	var remotePort *int = flag.Int("P", 3478, "remote server port")
	var localAddr *string = flag.String("h", "localhost", "address to bind to")
	var localPort *int = flag.Int("p", 6001, "local proxy port")
	var dtlsAddr *string = flag.String("D", "localhost", "DTLS server address")
	var dtlsPort *int = flag.Int("d", 8443, "DTLS server port")

	flag.Parse()

	log.SetOutput(os.Stdout)

	dtlsFound = false

	// has to be synchronous to give time for listeners
	targetConn, sourceConn, dtlsConn, ok := udpProxyPrepare(
		*remoteAddr, uint16(*remotePort),
		*localAddr, uint16(*localPort),
		*dtlsAddr, uint16(*dtlsPort))
	if !ok {
		panic(ok)
	}

	log.Printf("UDP demultiplexor, listen address %s, remote address %s.\n",
		*localAddr, *remoteAddr)

	udpProxyConnection(targetConn, sourceConn, dtlsConn)
}
