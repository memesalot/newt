package wgtester

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/fosrl/newt/logger"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

const (
	// Magic bytes to identify our packets
	magicHeader uint32 = 0xDEADBEEF
	// Request packet type
	packetTypeRequest uint8 = 1
	// Response packet type
	packetTypeResponse uint8 = 2
	// Packet format:
	// - 4 bytes: magic header (0xDEADBEEF)
	// - 1 byte: packet type (1 = request, 2 = response)
	// - 8 bytes: timestamp (for round-trip timing)
	packetSize = 13
)

// Server handles listening for connection check requests using UDP
type Server struct {
	conn         net.Conn     // Generic net.Conn interface (could be *net.UDPConn or *gonet.UDPConn)
	udpConn      *net.UDPConn // Regular UDP connection (when not using netstack)
	netstackConn interface{}  // Netstack UDP connection (when using netstack)
	serverAddr   string
	serverPort   uint16
	shutdownCh   chan struct{}
	isRunning    bool
	runningLock  sync.Mutex
	newtID       string
	outputPrefix string
	useNetstack  bool
	tnet         interface{} // Will be *netstack.Net when using netstack
}

// NewServer creates a new connection test server using UDP
func NewServer(serverAddr string, serverPort uint16, newtID string) *Server {
	return &Server{
		serverAddr:   serverAddr,
		serverPort:   serverPort + 1, // use the next port for the server
		shutdownCh:   make(chan struct{}),
		newtID:       newtID,
		outputPrefix: "[WGTester] ",
		useNetstack:  false,
		tnet:         nil,
	}
}

// NewServerWithNetstack creates a new connection test server using WireGuard netstack
func NewServerWithNetstack(serverAddr string, serverPort uint16, newtID string, tnet *netstack.Net) *Server {
	return &Server{
		serverAddr:   serverAddr,
		serverPort:   serverPort + 1, // use the next port for the server
		shutdownCh:   make(chan struct{}),
		newtID:       newtID,
		outputPrefix: "[WGTester] ",
		useNetstack:  true,
		tnet:         tnet,
	}
}

// Start begins listening for connection test packets using UDP
func (s *Server) Start() error {
	s.runningLock.Lock()
	defer s.runningLock.Unlock()

	if s.isRunning {
		return nil
	}

	//create the address to listen on
	addr := net.JoinHostPort(s.serverAddr, fmt.Sprintf("%d", s.serverPort))

	if s.useNetstack && s.tnet != nil {
		// Use WireGuard netstack
		tnet := s.tnet.(*netstack.Net)
		udpAddr := &net.UDPAddr{Port: int(s.serverPort)}
		netstackConn, err := tnet.ListenUDP(udpAddr)
		if err != nil {
			return err
		}
		s.netstackConn = netstackConn
		s.conn = netstackConn
	} else {
		// Use regular UDP socket
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}

		udpConn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return err
		}
		s.udpConn = udpConn
		s.conn = udpConn
	}

	s.isRunning = true
	go s.handleConnections()

	logger.Info("%sServer started on %s:%d", s.outputPrefix, s.serverAddr, s.serverPort)
	return nil
}

// Stop shuts down the server
func (s *Server) Stop() {
	s.runningLock.Lock()
	defer s.runningLock.Unlock()

	if !s.isRunning {
		return
	}

	close(s.shutdownCh)
	if s.conn != nil {
		s.conn.Close()
	}
	s.isRunning = false
	logger.Info("%sServer stopped", s.outputPrefix)
}

// RestartWithNetstack stops the current server and restarts it with netstack
func (s *Server) RestartWithNetstack(tnet *netstack.Net) error {
	s.Stop()

	// Update configuration to use netstack
	s.useNetstack = true
	s.tnet = tnet

	// Clear previous connections
	s.conn = nil
	s.udpConn = nil
	s.netstackConn = nil

	// Create new shutdown channel
	s.shutdownCh = make(chan struct{})

	// Restart the server
	return s.Start()
}

// handleConnections processes incoming packets
func (s *Server) handleConnections() {
	buffer := make([]byte, 2000) // Buffer large enough for any UDP packet

	for {
		select {
		case <-s.shutdownCh:
			return
		default:
			// Set read deadline to avoid blocking forever
			err := s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			if err != nil {
				logger.Error("%sError setting read deadline: %v", s.outputPrefix, err)
				continue
			}

			// Read from UDP connection - handle both regular UDP and netstack UDP
			var n int
			var addr net.Addr
			if s.useNetstack {
				// Use netstack UDP connection
				netstackConn := s.netstackConn.(*gonet.UDPConn)
				n, addr, err = netstackConn.ReadFrom(buffer)
			} else {
				// Use regular UDP connection
				n, addr, err = s.udpConn.ReadFromUDP(buffer)
			}

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// Just a timeout, keep going
					continue
				}
				// Check if we're shutting down and the connection was closed
				select {
				case <-s.shutdownCh:
					return // Don't log error if we're shutting down
				default:
					logger.Error("%sError reading from UDP: %v", s.outputPrefix, err)
				}
				continue
			}

			// Process packet only if it meets minimum size requirements
			if n < packetSize {
				continue // Too small to be our packet
			}

			// Check magic header
			magic := binary.BigEndian.Uint32(buffer[0:4])
			if magic != magicHeader {
				continue // Not our packet
			}

			// Check packet type
			packetType := buffer[4]
			if packetType != packetTypeRequest {
				continue // Not a request packet
			}

			// Create response packet
			responsePacket := make([]byte, packetSize)
			// Copy the same magic header
			binary.BigEndian.PutUint32(responsePacket[0:4], magicHeader)
			// Change the packet type to response
			responsePacket[4] = packetTypeResponse
			// Copy the timestamp (for RTT calculation)
			copy(responsePacket[5:13], buffer[5:13])

			// Log response being sent for debugging
			logger.Debug("%sSending response to %s", s.outputPrefix, addr.String())

			// Send the response packet - handle both regular UDP and netstack UDP
			if s.useNetstack {
				// Use netstack UDP connection
				netstackConn := s.netstackConn.(*gonet.UDPConn)
				_, err = netstackConn.WriteTo(responsePacket, addr)
			} else {
				// Use regular UDP connection
				udpAddr := addr.(*net.UDPAddr)
				_, err = s.udpConn.WriteToUDP(responsePacket, udpAddr)
			}

			if err != nil {
				logger.Error("%sError sending response: %v", s.outputPrefix, err)
			} else {
				logger.Debug("%sResponse sent successfully", s.outputPrefix)
			}
		}
	}
}
