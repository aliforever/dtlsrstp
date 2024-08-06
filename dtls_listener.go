package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v2"
)

type DTLSSRTPListener struct {
	listener net.Listener
	cancel   context.CancelFunc
	format   string
}

func (l *DTLSSRTPListener) Listen(rtpPackets chan<- *rtp.Packet) {
	for {
		ingress, err := l.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "listener closed") {
				break
			}

			fmt.Println("Could not accept DTLS SRTP connection")

			continue
		}

		ingress.Provide(rtpPackets)
	}
}

func (l *DTLSSRTPListener) Close() error {
	l.cancel()
	return l.listener.Close()
}

func (l *DTLSSRTPListener) Accept() (*SRTPIngress, error) {
	// Wait for a connection.
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("could not accept dtls srtp connection: %w", err)
	}

	dtlsConn, ok := conn.(*dtls.Conn)
	if !ok {
		return nil, fmt.Errorf("connection was not a dtls connection (impossible!)")
	}

	cert, err := x509.ParseCertificate(dtlsConn.ConnectionState().PeerCertificates[0])
	if err != nil {
		return nil, fmt.Errorf("could not parse server certificate: %w", err)
	}

	protectionProfile, ok := dtlsConn.SelectedSRTPProtectionProfile()
	if !ok {
		return nil, fmt.Errorf("no SRTPProtectionProfile has been chosen")
	}
	if protectionProfile != dtls.SRTP_AEAD_AES_128_GCM {
		return nil, fmt.Errorf("wrong SRTPProtectionProfile is in use (is %d, should be %d)", protectionProfile, dtls.SRTP_AEAD_AES_128_GCM)
	}

	dtlsConnState := dtlsConn.ConnectionState()
	srtpConfig := srtp.Config{
		Profile: srtp.ProtectionProfileAeadAes128Gcm,
	}
	err = srtpConfig.ExtractSessionKeysFromDTLS(&dtlsConnState, false)
	if err != nil {
		return nil, fmt.Errorf("could not extract session keys: %w", err)
	}

	srtpSession, err := srtp.NewSessionSRTP(dtlsConn, &srtpConfig)
	if err != nil {
		return nil, fmt.Errorf("could not start srtp session: %w", err)
	}

	return MakeSRTPIngress(cert.Subject.CommonName, srtpSession, l.format)
}

func NewDTLSListener(ip net.IP, port int, format string) (*DTLSSRTPListener, error) {
	return newDTLSListener(ip, port, format, false)
}

var (
	errBlockIsNotPrivateKey  = errors.New("block is not a private key, unable to load key")
	errUnknownKeyTime        = errors.New("unknown key time in PKCS#8 wrapping, unable to load key")
	errNoPrivateKeyFound     = errors.New("no private key found, unable to load key")
	errBlockIsNotCertificate = errors.New("block is not a certificate, unable to load certificates")
	errNoCertificateFound    = errors.New("no certificate found, unable to load certificates")
)

func LoadTLSCertificate(path string) (*tls.Certificate, error) {
	rawData, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	var certificate tls.Certificate

	for {
		block, rest := pem.Decode(rawData)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return nil, errBlockIsNotCertificate
		}

		certificate.Certificate = append(certificate.Certificate, block.Bytes)
		rawData = rest
	}

	if len(certificate.Certificate) == 0 {
		return nil, errNoCertificateFound
	}

	return &certificate, nil
}

// LoadKey Load/read key from file
func LoadKey(path string) (crypto.PrivateKey, error) {
	rawData, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(rawData)
	if block == nil || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, errBlockIsNotPrivateKey
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errUnknownKeyTime
		}
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errNoPrivateKeyFound
}

// LoadKeyAndCertificate reads certificates or key from file
func LoadKeyAndCertificate(keyPath, certPath string) (*tls.Certificate, error) {
	privateKey, err := LoadKey(keyPath)
	if err != nil {
		return nil, err
	}

	certificate, err := LoadTLSCertificate(certPath)
	if err != nil {
		return nil, err
	}

	certificate.PrivateKey = privateKey

	return certificate, nil
}

func newDTLSListener(ip net.IP, port int, format string, transcode bool) (*DTLSSRTPListener, error) {
	// Create parent context to clean up handshaking connections on exit.
	ctx, cancel := context.WithCancel(context.Background())

	certificate, err := LoadKeyAndCertificate("certificates/server.pem", "certificates/server.pub.pem")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("could not load key and certificate: %w", err)
	}

	// TODO: replace root certificate
	rootCertificate, err := LoadTLSCertificate("certificates/server.pub.pem")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("could not server certificate: %w", err)
	}

	certPool := x509.NewCertPool()
	cert, err := x509.ParseCertificate(rootCertificate.Certificate[0])
	if err != nil {
		cancel()
		return nil, fmt.Errorf("could not parse server certificate: %w", err)
	}
	certPool.AddCert(cert)

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		Certificates:         []tls.Certificate{*certificate},
		ClientAuth:           dtls.RequireAndVerifyClientCert,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ClientCAs:            certPool,

		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtls.SRTP_AEAD_AES_128_GCM},

		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil
		},

		// Create timeout context for accepted connection.
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(ctx, 30*time.Second)
		},
	}

	// Start the DTLS server
	listener, err := dtls.Listen("udp", &net.UDPAddr{IP: ip, Port: port}, config)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("could not start dtls listen: %w", err)
	}

	fmt.Println("dtls listener running")

	return &DTLSSRTPListener{
		listener: listener,
		cancel:   cancel,
		format:   format,
	}, nil
}
