package main

import (
	"fmt"
	"log"
	"net"

	"github.com/pion/rtp"
)

func main() {
	dtlsListenerIpParsed := net.ParseIP("0.0.0.0")

	rtpPackets := make(chan *rtp.Packet)

	go func() {
		for packet := range rtpPackets {
			_ = packet

			// These RTP packets then are written to LocalStaticTrack
		}
	}()

	listener, err := NewDTLSListener(dtlsListenerIpParsed, 5006, "h264")
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		err := listener.Close()
		if err != nil {
			fmt.Println("Could not close DTLS h264Listener")
		}
	}()
	go listener.Listen(rtpPackets)

	select {}
}
