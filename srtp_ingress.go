package main

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/pion/rtp"
	"github.com/pion/srtp/v2"
)

const (
	maxIngressErrorCount = 1000
)

type SRTPIngress struct {
	srtpSession *srtp.SessionSRTP
	providerID  string
	format      string

	writer io.Writer

	forwarding bool
	lock       sync.Mutex
}

func MakeSRTPIngress(
	providerID string,
	srtpSession *srtp.SessionSRTP,
	format string,
) (*SRTPIngress, error) {
	si := &SRTPIngress{
		providerID:  providerID,
		format:      format,
		srtpSession: srtpSession,
	}

	return si, nil
}

func (i *SRTPIngress) Close() error {
	return i.srtpSession.Close()
}

func (i *SRTPIngress) Provide(rtpPackets chan<- *rtp.Packet) {
	i.lock.Lock()
	defer i.lock.Unlock()

	if i.forwarding {
		fmt.Println("Provide called on SRTPIngress when already forwarding")
		return
	}
	i.forwarding = true

	go i.acceptStreams(rtpPackets)
}

func (i *SRTPIngress) acceptStreams(rtpPackets chan<- *rtp.Packet) {
	for {
		stream, ssrc, err := i.srtpSession.AcceptStream()
		if err != nil {
			fmt.Println("Could not accept stream for SRTPIngress")
			if strings.Contains(err.Error(), "already closed") { // TODO: really brittle, but the library does not give better errors
				break
			}
		}

		go i.forward(stream, rtpPackets, ssrc)
	}
}

func (i *SRTPIngress) forward(stream *srtp.ReadStreamSRTP, streamChan chan<- *rtp.Packet, ssrc uint32) {
	fmt.Println("Forwarding stream")

	errorCount := 0

	for {
		// IMPORTANT: we need to always allocate a new buffer, since we pass around pointers and rely on the content not
		// being overwritten as it is directly used in the unmarshalled rtp packet struct
		// TODO: performance could maybe be improved by using an arena allocator or something
		inboundRTPPacket := make([]byte, 1600) // UDP MTU
		ni, err := stream.Read(inboundRTPPacket)
		if err != nil {
			fmt.Println("Could not read from source")
			if err, ok := err.(net.Error); ok && !err.Timeout() {
				break
			}
			errorCount++
			if errorCount >= maxIngressErrorCount {
				break
			}
			continue
		}

		packet := rtp.Packet{}

		err = packet.Unmarshal(inboundRTPPacket[:ni])
		if err != nil {
			// fmt.Println("Could not unmarshal incoming packet", err)
			errorCount++
			if errorCount >= maxIngressErrorCount {
				break
			}

			continue
		}

		streamChan <- &packet
		errorCount = 0
	}
}
