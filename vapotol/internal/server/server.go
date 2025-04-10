
package server

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"valx.pw/vapotol/pkg/crypto"
	"valx.pw/vapotol/pkg/obfuscator"
	"valx.pw/vapotol/pkg/protocol"
	"github.com/miekg/dns"
	"encoding/base64"
)


type Options struct {
	ListenAddr      string
	EnableObfs      bool
	EnableMultiport bool
	TLSCertPath     string
	TLSKeyPath      string
	DNSDomain       string
	EnableDNSSEC    bool
}


type Server struct {
	options  Options
	listener net.Listener
	clients  map[string]*clientConn
	obfs     *obfuscator.Obfuscator
	crypto   *crypto.Cryptor
	mu       sync.RWMutex
	stop     chan struct{}
	connections map[uint32]*clientConn
	dnsClients  map[string]*dnsClientState
	dnsKey      *dns.DNSKEY
	logger      *log.Logger
}

type clientConn struct {
	conn       net.Conn
	lastActive time.Time
	buffer     []byte 
}


type dnsClientState struct {
	lastActivity time.Time
	connections  map[uint32]*clientConn
	clientID     string
}


func New(opts Options) (*Server, error) {
	if opts.ListenAddr == "" {
		return nil, errors.New("не указан адрес для прослушивания")
	}

	obfs := obfuscator.New()
	cryptor, err := crypto.New()
	if err != nil {
		return nil, err
	}

	return &Server{
		options: opts,
		clients: make(map[string]*clientConn),
		obfs:    obfs,
		crypto:  cryptor,
		stop:    make(chan struct{}),
		connections: make(map[uint32]*clientConn),
		dnsClients:  make(map[string]*dnsClientState),
		logger:  log.Default(),
	}, nil
}


func (s *Server) Start() error {
	var listener net.Listener
	var err error

	if s.options.TLSCertPath != "" && s.options.TLSKeyPath != "" {
		
		cert, err := tls.LoadX509KeyPair(s.options.TLSCertPath, s.options.TLSKeyPath)
		if err != nil {
			return err
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		listener, err = tls.Listen("tcp", s.options.ListenAddr, tlsConfig)
		log.Println("Запущен с TLS шифрованием")
	} else {
		
		listener, err = net.Listen("tcp", s.options.ListenAddr)
		log.Println("Запущен без TLS")
	}

	if err != nil {
		return err
	}

	s.listener = listener
	log.Printf("VPN-сервер запущен на %s", s.options.ListenAddr)

	if s.options.EnableMultiport {
		
		go s.startMultiportServers()
	}

	
	go s.cleanupInactiveClients()

	
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return nil
			default:
				log.Printf("Ошибка принятия соединения: %v", err)
				continue
			}
		}

		
		go s.handleConnection(conn)
	}
}


func (s *Server) Stop() {
	close(s.stop)
	if s.listener != nil {
		s.listener.Close()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	
	for _, client := range s.clients {
		client.conn.Close()
	}
	s.clients = make(map[string]*clientConn)
	log.Println("VPN-сервер остановлен")
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	
	clientID := conn.RemoteAddr().String()
	log.Printf("Новое подключение от: %s", clientID)

	
	s.mu.Lock()
	s.clients[clientID] = &clientConn{
		conn:       conn,
		lastActive: time.Now(),
	}
	s.mu.Unlock()

	
	if err := s.handleHandshake(conn); err != nil {
		log.Printf("Ошибка рукопожатия с %s: %v", clientID, err)
		s.mu.Lock()
		delete(s.clients, clientID)
		s.mu.Unlock()
		return
	}

	
	s.handleDataTransfer(conn, clientID)
}

func (s *Server) handleHandshake(conn net.Conn) error {
	
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{}) 

	
	buf := make([]byte, protocol.HandshakeSize)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	
	if s.options.EnableObfs {
		var err error
		buf, err = s.obfs.Deobfuscate(buf)
		if err != nil {
			return err
		}
	}

	
	if !protocol.ValidateHandshake(buf) {
		return errors.New("недействительное рукопожатие")
	}

	
	response := protocol.GenerateHandshakeResponse()
	if s.options.EnableObfs {
		response = s.obfs.Obfuscate(response)
	}

	if _, err := conn.Write(response); err != nil {
		return err
	}

	return nil
}

func (s *Server) handleDataTransfer(conn net.Conn, clientID string) {
	
	const dataTimeout = 30 * time.Minute
	
	for {
		select {
		case <-s.stop:
			return
		default:
			
			conn.SetReadDeadline(time.Now().Add(dataTimeout))

			
			headerBuf := make([]byte, protocol.HeaderSize)
			_, err := io.ReadFull(conn, headerBuf)
			if err != nil {
				if !errors.Is(err, io.EOF) {
					log.Printf("Ошибка чтения заголовка от %s: %v", clientID, err)
				}
				s.mu.Lock()
				delete(s.clients, clientID)
				s.mu.Unlock()
				return
			}

			
			if s.options.EnableObfs {
				headerBuf, err = s.obfs.Deobfuscate(headerBuf)
				if err != nil {
					log.Printf("Ошибка деобфускации заголовка от %s: %v", clientID, err)
					continue
				}
			}

			
			packetSize, packetType, err := protocol.ParseHeader(headerBuf)
			if err != nil {
				log.Printf("Ошибка разбора заголовка от %s: %v", clientID, err)
				continue
			}

			
			dataBuf := make([]byte, packetSize)
			_, err = io.ReadFull(conn, dataBuf)
			if err != nil {
				log.Printf("Ошибка чтения данных от %s: %v", clientID, err)
				continue
			}

			
			if s.options.EnableObfs {
				dataBuf, err = s.obfs.Deobfuscate(dataBuf)
				if err != nil {
					log.Printf("Ошибка деобфускации данных от %s: %v", clientID, err)
					continue
				}
			}

			dataBuf, err = s.crypto.Decrypt(dataBuf)
			if err != nil {
				log.Printf("Ошибка расшифровки данных от %s: %v", clientID, err)
				continue
			}

			
			switch packetType {
			case protocol.PacketTypeData:
				
				
				log.Printf("Получен пакет данных размером %d байт от %s", packetSize, clientID)
				
				
				s.sendAck(conn, clientID)

			case protocol.PacketTypePing:
				
				log.Printf("Получен ping от %s", clientID)
				s.sendPong(conn, clientID)

			default:
				log.Printf("Получен неизвестный тип пакета (%d) от %s", packetType, clientID)
			}

			
			s.mu.Lock()
			if client, ok := s.clients[clientID]; ok {
				client.lastActive = time.Now()
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) sendAck(conn net.Conn, clientID string) {
	ackPacket := protocol.GenerateAckPacket(0) 
	
	
	encData, err := s.crypto.Encrypt(ackPacket.Data)
	if err != nil {
		log.Printf("Ошибка шифрования ACK для %s: %v", clientID, err)
		return
	}
	
	ackPacket.Data = encData
	
	
	headerBytes := protocol.GenerateHeader(uint32(len(ackPacket.Data)), ackPacket.Header.PacketType)
	
	if s.options.EnableObfs {
		headerBytes = s.obfs.Obfuscate(headerBytes)
		ackPacket.Data = s.obfs.Obfuscate(ackPacket.Data)
	}
	
	
	if _, err := conn.Write(headerBytes); err != nil {
		log.Printf("Ошибка отправки заголовка ACK для %s: %v", clientID, err)
		return
	}
	
	if _, err := conn.Write(ackPacket.Data); err != nil {
		log.Printf("Ошибка отправки данных ACK для %s: %v", clientID, err)
	}
}

func (s *Server) sendPong(conn net.Conn, clientID string) {
	
	pingData := make([]byte, 8)
	binary.BigEndian.PutUint64(pingData, uint64(time.Now().UnixNano()))
	
	pongPacket := protocol.GeneratePongPacket(pingData)
	
	
	encData, err := s.crypto.Encrypt(pongPacket.Data)
	if err != nil {
		log.Printf("Ошибка шифрования PONG для %s: %v", clientID, err)
		return
	}
	
	pongPacket.Data = encData
	
	
	headerBytes := protocol.GenerateHeader(uint32(len(pongPacket.Data)), pongPacket.Header.PacketType)
	
	if s.options.EnableObfs {
		headerBytes = s.obfs.Obfuscate(headerBytes)
		pongPacket.Data = s.obfs.Obfuscate(pongPacket.Data)
	}
	
	
	if _, err := conn.Write(headerBytes); err != nil {
		log.Printf("Ошибка отправки заголовка PONG для %s: %v", clientID, err)
		return
	}
	
	if _, err := conn.Write(pongPacket.Data); err != nil {
		log.Printf("Ошибка отправки данных PONG для %s: %v", clientID, err)
	}
}

func (s *Server) cleanupInactiveClients() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for id, client := range s.clients {
				if now.Sub(client.lastActive) > 30*time.Minute {
					log.Printf("Закрытие неактивного соединения: %s", id)
					client.conn.Close()
					delete(s.clients, id)
				}
			}
			s.mu.Unlock()
		case <-s.stop:
			return
		}
	}
}

func (s *Server) startMultiportServers() {
	
	
	
	
	go s.startHTTPCamouflageServer(":80")
	
	
	go s.startDNSCamouflageServer(":53")
}

func (s *Server) startHTTPCamouflageServer(addr string) {
	
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Не удалось запустить HTTP-камуфляж на %s: %v", addr, err)
		return
	}
	defer listener.Close()
	
	log.Printf("HTTP-камуфляж запущен на %s", addr)
	
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
				log.Printf("Ошибка принятия HTTP-соединения: %v", err)
				continue
			}
		}
		
		go s.handleHTTPCamouflage(conn)
	}
}

func (s *Server) handleHTTPCamouflage(conn net.Conn) {
	defer conn.Close()
	
	
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	
	
	if s.isVapotolOverHTTP(buf[:n]) {
		
		s.handleVapotolOverHTTP(conn, buf[:n])
	} else {
		
		s.respondWithFakeHTTP(conn)
	}
}

func (s *Server) isVapotolOverHTTP(data []byte) bool {
	if len(data) < 10 {
		return false
	}
	
	if bytes.HasPrefix(data, []byte("GET ")) || bytes.HasPrefix(data, []byte("POST ")) {
		return protocol.ContainsVapotolMarker(data)
	}
	
	if bytes.HasPrefix(data, []byte("CONNECT ")) {
		return protocol.ContainsVapotolMarker(data)
	}
	
	return false
}

func (s *Server) handleVapotolOverHTTP(conn net.Conn, initialData []byte) {
	clientID := conn.RemoteAddr().String()
	
	if len(initialData) > 4 && initialData[0] == 'P' && initialData[1] == 'O' && initialData[2] == 'S' && initialData[3] == 'T' {
		s.handlePOSTRequest(conn, initialData, clientID)
		return
	}
	
	if len(initialData) > 7 && initialData[0] == 'C' && initialData[1] == 'O' && initialData[2] == 'N' && 
	   initialData[3] == 'N' && initialData[4] == 'E' && initialData[5] == 'C' && initialData[6] == 'T' {
		s.handleCONNECTRequest(conn, initialData, clientID)
		return
	}
	
	httpResponse := protocol.GenerateHTTPCamouflagedResponse()
	conn.Write(httpResponse)
	
	s.mu.Lock()
	s.clients[clientID] = &clientConn{
		conn:       conn,
		lastActive: time.Now(),
	}
	s.mu.Unlock()
	
	s.handleDataTransfer(conn, clientID)
}

func (s *Server) handlePOSTRequest(conn net.Conn, initialData []byte, clientID string) {
	var contentLength int
	var headerEnd int
	
	headerLines := bytes.Split(initialData, []byte("\r\n"))
	for i, line := range headerLines {
		if len(line) == 0 {
			headerEnd = i
			break
		}
		
		if bytes.HasPrefix(bytes.ToLower(line), []byte("content-length:")) {
			parts := bytes.SplitN(line, []byte(":"), 2)
			if len(parts) == 2 {
				clStr := strings.TrimSpace(string(parts[1]))
				if cl, err := strconv.Atoi(clStr); err == nil {
					contentLength = cl
				}
			}
		}
	}
	
	if contentLength > 0 && headerEnd > 0 {
		bodyStart := bytes.Index(initialData, []byte("\r\n\r\n")) + 4
		if bodyStart > 4 && len(initialData) >= bodyStart {
			bodyReceived := len(initialData) - bodyStart
			
			if bodyReceived < contentLength {
				remainingBytes := contentLength - bodyReceived
				bodyBuffer := make([]byte, remainingBytes)
				
				_, err := io.ReadFull(conn, bodyBuffer)
				if err != nil {
					s.respondWithFakeHTTP(conn)
					return
				}
				
				fullBody := append(initialData[bodyStart:], bodyBuffer...)
				
				if s.processHTTPBody(fullBody, conn, clientID) {
					return
				}
			} else {
				if s.processHTTPBody(initialData[bodyStart:bodyStart+contentLength], conn, clientID) {
					return
				}
			}
		}
	}
	
	s.respondWithFakeHTTP(conn)
}

func (s *Server) handleCONNECTRequest(conn net.Conn, initialData []byte, clientID string) {
	response := "HTTP/1.1 200 Connection Established\r\n" +
		"Proxy-agent: VAPOtol/" + protocol.Version + "\r\n" +
		"X-Vapotol-Ack: " + protocol.GenerateRandomHexString(32) + "\r\n\r\n"
	
	conn.Write([]byte(response))
	
	s.mu.Lock()
	s.clients[clientID] = &clientConn{
		conn:       conn,
		lastActive: time.Now(),
	}
	s.mu.Unlock()
	
	s.handleDataTransfer(conn, clientID)
}

func (s *Server) processHTTPBody(body []byte, conn net.Conn, clientID string) bool {
	if len(body) < 8 {
		return false
	}
	
	if !bytes.Equal(body[:4], []byte{0xFA, 0xCE, 0xB0, 0x0C}) {
		return false
	}
	
	packetSize := binary.BigEndian.Uint32(body[4:8])
	if len(body) < 8+int(packetSize) {
		return false
	}
	
	packetData := body[8:8+packetSize]
	
	var err error
	if s.options.EnableObfs {
		packetData, err = s.obfs.Deobfuscate(packetData)
		if err != nil {
			return false
		}
	}
	
	headerSize := protocol.HeaderSize
	if len(packetData) < headerSize {
		return false
	}
	
	packetHeader := packetData[:headerSize]
	_, packetType, err := protocol.ParseHeader(packetHeader)
	if err != nil {
		return false
	}
	
	if packetType == protocol.PacketTypeHandshake {
		response := "HTTP/1.1 200 OK\r\n" +
			"Server: nginx/1.18.0\r\n" +
			"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
			"Content-Type: application/octet-stream\r\n" +
			"Cache-Control: no-cache\r\n" +
			"X-Vapotol-Ack: " + protocol.GenerateRandomHexString(32) + "\r\n" +
			"Connection: keep-alive\r\n"
		
		handshakeResp := protocol.GenerateHandshakeResponse()
		if s.options.EnableObfs {
			handshakeResp = s.obfs.Obfuscate(handshakeResp)
		}
		
		wrappedResp := make([]byte, 8+len(handshakeResp))
		copy(wrappedResp[:4], []byte{0xFA, 0xCE, 0xB0, 0x0C})
		binary.BigEndian.PutUint32(wrappedResp[4:8], uint32(len(handshakeResp)))
		copy(wrappedResp[8:], handshakeResp)
		
		response += "Content-Length: " + strconv.Itoa(len(wrappedResp)) + "\r\n\r\n"
		conn.Write([]byte(response))
		conn.Write(wrappedResp)
		
		s.mu.Lock()
		s.clients[clientID] = &clientConn{
			conn:       conn,
			lastActive: time.Now(),
		}
		s.mu.Unlock()
		
		go s.handleHTTPPersistentConnection(conn, clientID)
		return true
	}
	
	return false
}

func (s *Server) handleHTTPPersistentConnection(conn net.Conn, clientID string) {
	defer func() {
		conn.Close()
		
		s.mu.Lock()
		delete(s.clients, clientID)
		s.mu.Unlock()
	}()
	
	header := make([]byte, 4)
	
	for {
		select {
		case <-s.stop:
			return
		default:
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			
			_, err := io.ReadFull(conn, header)
			if err != nil {
				return
			}
			
			if !bytes.Equal(header, []byte{0xFA, 0xCE, 0xB0, 0x0C}) {
				return
			}
			
			var sizeBytes [4]byte
			_, err = io.ReadFull(conn, sizeBytes[:])
			if err != nil {
				return
			}
			
			size := binary.BigEndian.Uint32(sizeBytes[:])
			if size > 1024*1024 {
				return
			}
			
			packetData := make([]byte, size)
			_, err = io.ReadFull(conn, packetData)
			if err != nil {
				return
			}
			
			s.mu.Lock()
			client, exists := s.clients[clientID]
			if exists {
				client.lastActive = time.Now()
			}
			s.mu.Unlock()
			
			if !exists {
				return
			}
			
			if s.options.EnableObfs {
				var err error
				packetData, err = s.obfs.Deobfuscate(packetData)
				if err != nil {
					continue
				}
			}
			
			headerSize := protocol.HeaderSize
			if len(packetData) < headerSize {
				continue
			}
			
			packetHeader := packetData[:headerSize]
			packetSize, packetType, err := protocol.ParseHeader(packetHeader)
			if err != nil {
				continue
			}
			
			if len(packetData) < headerSize+int(packetSize) {
				continue
			}
			
			packet := packetData[headerSize:headerSize+int(packetSize)]
			
			packet, err = s.crypto.Decrypt(packet)
			if err != nil {
				continue
			}
			
			responseData := s.processPacket(packetType, packet, clientID)
			if responseData != nil {
				encData, err := s.crypto.Encrypt(responseData)
				if err != nil {
					continue
				}
				
				header := protocol.GenerateHeader(uint32(len(encData)), packetType+0x80)
				
				if s.options.EnableObfs {
					header = s.obfs.Obfuscate(header)
					encData = s.obfs.Obfuscate(encData)
				}
				
				fullResp := make([]byte, 8+len(header)+len(encData))
				copy(fullResp[:4], []byte{0xFA, 0xCE, 0xB0, 0x0C})
				binary.BigEndian.PutUint32(fullResp[4:8], uint32(len(header)+len(encData)))
				copy(fullResp[8:], header)
				copy(fullResp[8+len(header):], encData)
				
				conn.Write(fullResp)
			}
		}
	}
}

func (s *Server) processPacket(packetType byte, data []byte, clientID string) []byte {
	switch packetType {
	case protocol.PacketTypePing:
		
		pingData := make([]byte, 8)
		binary.BigEndian.PutUint64(pingData, uint64(time.Now().UnixNano()))
		return protocol.GeneratePongPacket(pingData).Data
	
	case protocol.PacketTypeConnect:
		if len(data) < 5 {
			return nil
		}
		
		connID := binary.BigEndian.Uint32(data[:4])
		
		endIdx := 4
		for i := 4; i < len(data); i++ {
			if data[i] == 0 {
				endIdx = i
				break
			}
		}
		
		if endIdx <= 4 {
			return nil
		}
		
		targetAddr := string(data[4:endIdx])
		
		conn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
		if err != nil {
			responseData := make([]byte, 8)
			binary.BigEndian.PutUint32(responseData[:4], connID)
			binary.BigEndian.PutUint32(responseData[4:], 1) 
			return responseData
		}
		
		newClientID := fmt.Sprintf("%s-%d", clientID, connID)
		
		s.mu.Lock()
		s.clients[newClientID] = &clientConn{
			conn:       conn,
			lastActive: time.Now(),
		}
		s.mu.Unlock()
		
		go s.handleTargetConnection(conn, newClientID, clientID, connID)
		
		responseData := make([]byte, 8)
		binary.BigEndian.PutUint32(responseData[:4], connID)
		binary.BigEndian.PutUint32(responseData[4:], 0) 
		return responseData
	
	case protocol.PacketTypeData:
		if len(data) < 4 {
			return nil
		}
		
		connID := binary.BigEndian.Uint32(data[:4])
		newClientID := fmt.Sprintf("%s-%d", clientID, connID)
		
		s.mu.RLock()
		targetConn, exists := s.clients[newClientID]
		s.mu.RUnlock()
		
		if !exists || targetConn.conn == nil {
			responseData := make([]byte, 8)
			binary.BigEndian.PutUint32(responseData[:4], connID)
			binary.BigEndian.PutUint32(responseData[4:], 2) 
			return responseData
		}
		
		if len(data) > 4 {
			_, err := targetConn.conn.Write(data[4:])
			if err != nil {
				responseData := make([]byte, 8)
				binary.BigEndian.PutUint32(responseData[:4], connID)
				binary.BigEndian.PutUint32(responseData[4:], 3) 
				return responseData
			}
			
			s.mu.Lock()
			targetConn.lastActive = time.Now()
			s.mu.Unlock()
		}
		
		responseData := make([]byte, 8)
		binary.BigEndian.PutUint32(responseData[:4], connID)
		binary.BigEndian.PutUint32(responseData[4:], 0) 
		return responseData
	
	case protocol.PacketTypeClose:
		if len(data) < 4 {
			return nil
		}
		
		connID := binary.BigEndian.Uint32(data[:4])
		newClientID := fmt.Sprintf("%s-%d", clientID, connID)
		
		s.mu.Lock()
		if targetConn, exists := s.clients[newClientID]; exists {
			if targetConn.conn != nil {
				targetConn.conn.Close()
			}
			delete(s.clients, newClientID)
		}
		s.mu.Unlock()
		
		responseData := make([]byte, 8)
		binary.BigEndian.PutUint32(responseData[:4], connID)
		binary.BigEndian.PutUint32(responseData[4:], 0) 
		return responseData
	
	default:
		return nil
	}
}

func (s *Server) handleTargetConnection(conn net.Conn, newClientID, parentID string, connID uint32) {
	defer func() {
		conn.Close()
		
		s.mu.Lock()
		delete(s.clients, newClientID)
		s.mu.Unlock()
	}()
	
	buffer := make([]byte, 4096)
	
	for {
		select {
		case <-s.stop:
			return
		default:
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			
			n, err := conn.Read(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}
			
			if n > 0 {
				s.mu.Lock()
				parent, exists := s.clients[parentID]
				if !exists || parent.conn == nil {
					s.mu.Unlock()
					return
				}
				
				client, exists := s.clients[newClientID]
				if exists {
					client.lastActive = time.Now()
				}
				s.mu.Unlock()
				
				dataPacket := make([]byte, 4+n)
				binary.BigEndian.PutUint32(dataPacket[:4], connID)
				copy(dataPacket[4:], buffer[:n])
				
				encData, err := s.crypto.Encrypt(dataPacket)
				if err != nil {
					continue
				}
				
				header := protocol.GenerateHeader(uint32(len(encData)), protocol.PacketTypeData)
				
				if s.options.EnableObfs {
					header = s.obfs.Obfuscate(header)
					encData = s.obfs.Obfuscate(encData)
				}
				
				fullResp := make([]byte, 8+len(header)+len(encData))
				copy(fullResp[:4], []byte{0xFA, 0xCE, 0xB0, 0x0C})
				binary.BigEndian.PutUint32(fullResp[4:8], uint32(len(header)+len(encData)))
				copy(fullResp[8:], header)
				copy(fullResp[8+len(header):], encData)
				
				parent.conn.Write(fullResp)
			}
		}
	}
}

func (s *Server) respondWithFakeHTTP(conn net.Conn) {
	
	response := "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.18.0\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Length: 143\r\n" +
		"Connection: close\r\n\r\n" +
		"<html><head><title>Welcome</title></head><body><h1>Welcome</h1><p>This server is working properly.</p></body></html>"
	
	conn.Write([]byte(response))
}

func (s *Server) startDNSCamouflageServer(addr string) {
	
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Printf("Не удалось разрешить UDP-адрес %s: %v", addr, err)
		return
	}
	
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("Не удалось запустить DNS-камуфляж на %s: %v", addr, err)
		return
	}
	defer conn.Close()
	
	log.Printf("DNS-камуфляж запущен на %s", addr)
	
	buffer := make([]byte, 1024)
	for {
		select {
		case <-s.stop:
			return
		default:
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("Ошибка чтения UDP: %v", err)
				continue
			}
			
			go s.handleDNSCamouflage(conn, addr, buffer[:n])
		}
	}
}

func (s *Server) handleDNSCamouflage(conn *net.UDPConn, addr *net.UDPAddr, data []byte) {
	if protocol.IsVapotolOverDNS(data) {
		
		response := protocol.GenerateFakeDNSResponse(data)
		conn.WriteToUDP(response, addr)
	} else {
		response := protocol.GenerateFakeDNSResponse(data)
		conn.WriteToUDP(response, addr)
	}
}


func (s *Server) processVapotolOverDNS(w dns.ResponseWriter, r *dns.Msg) {
	
	m := new(dns.Msg)
	m.SetReply(r)
	w.WriteMsg(m)
}


func (s *Server) isDNSRequestForService(domain string) bool {
	
	return strings.HasSuffix(domain, s.options.DNSDomain+".")
}


func (s *Server) extractPayloadFromDomain(domain string) ([]byte, error) {
	
	payload := strings.TrimSuffix(domain, s.options.DNSDomain+".")
	
	
	parts := strings.Split(payload, ".")
	
	
	var encodedData strings.Builder
	for _, part := range parts {
		encodedData.WriteString(part)
	}
	
	
	return base64.RawURLEncoding.DecodeString(encodedData.String())
}


func (s *Server) sendDNSError(w dns.ResponseWriter, r *dns.Msg, rcode int) {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	w.WriteMsg(m)
}


func (s *Server) sendDNSResponse(w dns.ResponseWriter, r *dns.Msg, data []byte, qtype uint16) {
	m := new(dns.Msg)
	m.SetReply(r)
	
	
	ttl := uint32(60) 
	
	switch qtype {
	case dns.TypeTXT:
		
		
		txt := []string{}
		
		
		encoded := base64.StdEncoding.EncodeToString(data)
		
		
		for i := 0; i < len(encoded); i += 255 {
			end := i + 255
			if end > len(encoded) {
				end = len(encoded)
			}
			txt = append(txt, encoded[i:end])
		}
		
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Txt: txt,
		}
		m.Answer = append(m.Answer, rr)
		
	case dns.TypeA:
		
		ip := net.IPv4(127, 0, 0, 1) 
		
		if len(data) >= 4 {
			ip = net.IPv4(data[0], data[1], data[2], data[3])
		}
		
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			A: ip,
		}
		m.Answer = append(m.Answer, rr)
		
	case dns.TypeAAAA:
		
		ip := net.ParseIP("::1") 
		
		if len(data) >= 16 {
			ip = net.IP(data[0:16])
		}
		
		rr := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			AAAA: ip,
		}
		m.Answer = append(m.Answer, rr)
	}
	
	
	if s.options.EnableDNSSEC && s.dnsKey != nil {
		m.AuthenticatedData = true
		
		
		s.signDNSResponse(m)
	}
	
	w.WriteMsg(m)
}


func (s *Server) signDNSResponse(m *dns.Msg) {
	if s.dnsKey == nil {
		return
	}
	
	
	m.Answer = append(m.Answer, s.dnsKey)
	
	
	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   s.options.DNSDomain + ".",
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Algorithm:  s.dnsKey.Algorithm,
		SignerName: s.options.DNSDomain + ".",
		KeyTag:     s.dnsKey.KeyTag(),
		Inception:  uint32(time.Now().Add(-1 * time.Hour).Unix()),
		Expiration: uint32(time.Now().Add(24 * time.Hour).Unix()),
	}
	
	
	m.Answer = append(m.Answer, rrsig)
}


func (s *Server) handleDNSConnect(connID uint32, data []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	
	if _, exists := s.connections[connID]; exists {
		
		log.Printf("Попытка создать существующее соединение, connID: %d", connID)
		responseHeader := []byte{protocol.PacketTypeError, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(responseHeader[1:5], connID)
		return responseHeader
	}
	
	
	if len(data) < 2 {
		log.Printf("Недостаточно данных в запросе на соединение")
		return nil
	}
	
	targetType := data[0]
	targetLen := int(data[1])
	
	if len(data) < 2+targetLen {
		log.Printf("Недостаточно данных для адреса назначения")
		return nil
	}
	
	targetAddr := string(data[2 : 2+targetLen])
	
	
	var target string
	switch targetType {
	case protocol.TargetTypeDomain:
		target = targetAddr
	case protocol.TargetTypeIPv4, protocol.TargetTypeIPv6:
		target = targetAddr
	default:
		log.Printf("Неизвестный тип адреса, type: %d", targetType)
		return nil
	}
	
	
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("Ошибка соединения с целевым адресом, target: %s, error: %v", target, err)
		
		
		responseHeader := []byte{protocol.PacketTypeError, 0, 0, 0, 0, protocol.ErrorConnectionFailed}
		binary.BigEndian.PutUint32(responseHeader[1:5], connID)
		return responseHeader
	}
	
	
	s.connections[connID] = &clientConn{
		conn:         conn,
		lastActive:   time.Now(),
	}
	
	
	go s.readFromTarget(connID)
	
	
	responseHeader := []byte{protocol.PacketTypeConnectOK, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(responseHeader[1:5], connID)
	return responseHeader
}


func (s *Server) handleDNSData(connID uint32, data []byte) []byte {
	
	s.mu.Lock()
	conn, exists := s.connections[connID]
	s.mu.Unlock()
	
	if !exists {
		
		log.Printf("Получены данные для несуществующего соединения, connID: %d", connID)
		responseHeader := []byte{protocol.PacketTypeError, 0, 0, 0, 0, protocol.ErrorConnectionNotFound}
		binary.BigEndian.PutUint32(responseHeader[1:5], connID)
		return responseHeader
	}
	
	
	_, err := conn.conn.Write(data)
	if err != nil {
		log.Printf("Ошибка отправки данных в целевое соединение, connID: %d, error: %v", connID, err)
		
		
		conn.conn.Close()
		s.mu.Lock()
		delete(s.connections, connID)
		s.mu.Unlock()
		
		
		responseHeader := []byte{protocol.PacketTypeError, 0, 0, 0, 0, protocol.ErrorWriteFailed}
		binary.BigEndian.PutUint32(responseHeader[1:5], connID)
		return responseHeader
	}
	
	
	s.mu.Lock()
	conn.lastActive = time.Now()
	s.mu.Unlock()
	
	
	responseHeader := []byte{protocol.PacketTypeAck, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(responseHeader[1:5], connID)
	return responseHeader
}


func (s *Server) handleDNSPing(connID uint32) []byte {
	
	responseHeader := []byte{protocol.PacketTypePong, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(responseHeader[1:5], connID)
	return responseHeader
}


func (s *Server) handleDNSClose(connID uint32) []byte {
	
	s.closeConnection(connID)
	
	
	responseHeader := []byte{protocol.PacketTypeCloseACK, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(responseHeader[1:5], connID)
	return responseHeader
}


func (s *Server) closeConnection(connID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	conn, exists := s.connections[connID]
	if exists {
		conn.conn.Close()
		delete(s.connections, connID)
	}
}


func (s *Server) readFromTarget(connID uint32) {
	defer func() {
		
		if r := recover(); r != nil {
			log.Printf("Panic in readFromTarget, error: %v", r)
		}
	}()
	
	s.mu.Lock()
	conn, exists := s.connections[connID]
	if !exists {
		s.mu.Unlock()
		return
	}
	
	
	buffer := make([]byte, 4096)
	
	for {
		
		conn.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		
		
		n, err := conn.conn.Read(buffer)
		
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				
				continue
			}
			
			
			s.closeConnection(connID)
			return
		}
		
		if n > 0 {
			s.mu.Lock()
			
			
			conn.buffer = append(conn.buffer, buffer[:n]...)
			
			s.mu.Unlock()
		}
	}
}


func (s *Server) startDNSClientCleaner() {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		
		for {
			select {
			case <-ticker.C:
				s.cleanInactiveDNSClients()
			case <-s.stop:
				return
			}
		}
	}()
}


func (s *Server) cleanInactiveDNSClients() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	now := time.Now()
	
	for clientID, client := range s.dnsClients {
		
		if now.Sub(client.lastActivity) > 5*time.Minute {
			
			for _, conn := range client.connections {
				conn.conn.Close()
			}
			
			
			delete(s.dnsClients, clientID)
		} else {
			
			for connID, conn := range client.connections {
				if now.Sub(conn.lastActive) > 2*time.Minute {
					
					conn.conn.Close()
					delete(client.connections, connID)
				}
			}
		}
	}
} 