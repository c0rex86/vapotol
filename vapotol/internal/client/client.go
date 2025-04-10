
package client

import (
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
	"valx.pw/vapotol/pkg/crypto"
	"valx.pw/vapotol/pkg/obfuscator"
	"valx.pw/vapotol/pkg/protocol"
)


type Options struct {
	ServerAddr    string
	LocalAddr     string
	EnableObfs    bool
	AutoReconn    bool
	UseTLS        bool
	UseTUN        bool    
	TUNName       string  
	TUNLocalIP    string  
	TUNRemoteIP   string  
	TUNRouteAll   bool    
	MimicHTTPS    bool    
	NaturalTiming bool    
	MimicDNS      bool    
	MimicWebRTC   bool    
}


type Client struct {
	options     Options
	conn        net.Conn
	mu          sync.Mutex
	stop        chan struct{}
	socksServer net.Listener
	obfs        *obfuscator.Obfuscator
	crypto      *crypto.Cryptor
	isConnected bool
	reconnLock  sync.Mutex
	lastActivity time.Time
	lastPing     time.Time
	recentSYNCount int
	connections     map[uint32]time.Time 
	sockConnections map[uint32]*sockConnection 
	tunIface    *water.Interface  
	tunCidr     *net.IPNet        
	logger      *logrus.Logger
	dataPreprocessor func([]byte) ([]byte, bool)
	stats       struct {
		inPackets  uint64
		outPackets uint64
		inBytes    uint64
		outBytes   uint64
	}
}


type clientConnection struct {
	lastActivity time.Time
	sourceAddr   string
	targetAddr   string
}


type sockConnection struct {
	conn     net.Conn
	lastSeen time.Time
}


const TUNConnID uint32 = 0 


func New(opts Options) (*Client, error) {
	if opts.ServerAddr == "" {
		return nil, errors.New("не указан адрес сервера")
	}
	if opts.LocalAddr == "" {
		return nil, errors.New("не указан локальный адрес для SOCKS-прокси")
	}

	obfs := obfuscator.New()
	cryptor, err := crypto.New()
	if err != nil {
		return nil, err
	}
	
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)

	return &Client{
		options: opts,
		obfs:    obfs,
		crypto:  cryptor,
		stop:    make(chan struct{}),
		connections: make(map[uint32]time.Time),
		sockConnections: make(map[uint32]*sockConnection),
		logger:   logger,
		lastActivity: time.Now(),
		lastPing: time.Now(),
	}, nil
}


func (c *Client) Start() error {
	
	if err := c.connect(); err != nil {
		return err
	}

	
	if err := c.startSocksServer(); err != nil {
		c.conn.Close()
		return err
	}

	
	go c.keepAlive()

	return nil
}


func (c *Client) Stop() {
	close(c.stop)
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	
	if c.socksServer != nil {
		c.socksServer.Close()
		c.socksServer = nil
	}
	
	c.isConnected = false
	c.logger.Info("VPN-клиент остановлен")
}

func (c *Client) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	var conn net.Conn
	var err error

	if c.options.UseTLS {
		
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, 
		}
		conn, err = tls.Dial("tcp", c.options.ServerAddr, tlsConfig)
		c.logger.Info("Подключение через TLS")
	} else {
		
		conn, err = net.Dial("tcp", c.options.ServerAddr)
		c.logger.Info("Подключение через TCP")
	}

	if err != nil {
		return err
	}

	c.logger.Infof("Подключен к серверу %s", c.options.ServerAddr)
	c.conn = conn
	
	
	if err := c.performHandshake(); err != nil {
		c.conn.Close()
		c.conn = nil
		return err
	}
	
	c.isConnected = true
	return nil
}

func (c *Client) performHandshake() error {
	
	c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.conn.SetDeadline(time.Time{}) 

	
	handshake := protocol.GenerateHandshake()
	
	
	if c.options.EnableObfs {
		handshake = c.obfs.Obfuscate(handshake)
	}

	
	if _, err := c.conn.Write(handshake); err != nil {
		return err
	}

	
	responseBuf := make([]byte, protocol.HandshakeResponseSize)
	if _, err := io.ReadFull(c.conn, responseBuf); err != nil {
		return err
	}

	
	if c.options.EnableObfs {
		var err error
		responseBuf, err = c.obfs.Deobfuscate(responseBuf)
		if err != nil {
			return err
		}
	}

	
	if !protocol.ValidateHandshakeResponse(responseBuf) {
		return errors.New("недействительный ответ сервера")
	}

	c.logger.Info("Рукопожатие успешно завершено")
	return nil
}

func (c *Client) startSocksServer() error {
	listener, err := net.Listen("tcp", c.options.LocalAddr)
	if err != nil {
		return err
	}

	c.socksServer = listener
	c.logger.Infof("SOCKS5-прокси запущен на %s", c.options.LocalAddr)

	
	go c.handleSocksConnections()

	return nil
}

func (c *Client) handleSocksConnections() {
	for {
		select {
		case <-c.stop:
			return
		default:
			c.socksServer.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
			conn, err := c.socksServer.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				c.logger.Errorf("Ошибка принятия SOCKS-соединения: %v", err)
				continue
			}

			go c.handleSocksClient(conn)
		}
	}
}

func (c *Client) handleSocksClient(clientConn net.Conn) {
	defer clientConn.Close()

	
	if err := c.handleSocksHandshake(clientConn); err != nil {
		c.logger.Errorf("Ошибка SOCKS-рукопожатия: %v", err)
		return
	}

	
	targetAddr, err := c.handleSocksRequest(clientConn)
	if err != nil {
		c.logger.Errorf("Ошибка SOCKS-запроса: %v", err)
		return
	}

	
	connID, err := c.sendConnectRequest(targetAddr)
	if err != nil {
		c.logger.Errorf("Ошибка запроса соединения к серверу: %v", err)
		return
	}

	
	c.proxyData(clientConn, connID)
}

func (c *Client) handleSocksHandshake(conn net.Conn) error {
	buf := make([]byte, 257)
	if _, err := conn.Read(buf[:2]); err != nil {
		return err
	}
	
	version := buf[0]
	if version != 5 {
		return errors.New("неподдерживаемая версия SOCKS")
	}
	
	nmethods := buf[1]
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return err
	}
	
	hasNoAuth := false
	for i := 0; i < int(nmethods); i++ {
		if buf[i] == 0 {
			hasNoAuth = true
			break
		}
	}
	
	if !hasNoAuth {
		conn.Write([]byte{5, 0xff})
		return errors.New("требуется аутентификация")
	}
	
	resp := []byte{5, 0}
	if _, err := conn.Write(resp); err != nil {
		return err
	}
	
	return nil
}

func (c *Client) handleSocksRequest(conn net.Conn) (string, error) {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return "", err
	}
	
	if buf[0] != 5 {
		return "", errors.New("неверная версия SOCKS")
	}
	
	if buf[1] != 1 {
		conn.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", errors.New("неподдерживаемая команда SOCKS")
	}
	
	if _, err := io.ReadFull(conn, buf[:1]); err != nil {
		return "", err
	}
	
	addrType := buf[0]
	var targetAddr string
	
	switch addrType {
	case 1:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return "", err
		}
		
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
			addr[0], addr[1], addr[2], addr[3],
			(int(port[0])<<8)|int(port[1]))
		
	case 3:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return "", err
		}
		
		addrLen := buf[0]
		addr := make([]byte, addrLen)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return "", err
		}
		
		targetAddr = fmt.Sprintf("%s:%d", 
			string(addr), 
			(int(port[0])<<8)|int(port[1]))
		
	case 4:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return "", err
		}
		
		ipv6 := net.IP(addr)
		targetAddr = fmt.Sprintf("[%s]:%d", 
			ipv6.String(), 
			(int(port[0])<<8)|int(port[1]))

	default:
		conn.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return "", errors.New("неподдерживаемый тип адреса")
	}
	
	response := []byte{
		5,    
		0,    
		0,    
		1,    
		0, 0, 0, 0, 
		0, 0, 
	}
	
	if _, err := conn.Write(response); err != nil {
		return "", err
	}
	
	return targetAddr, nil
}

func (c *Client) sendConnectRequest(targetAddr string) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if !c.isConnected {
		return 0, errors.New("не подключен к серверу")
	}
	
	
	connID := protocol.GenerateConnectionID()
	
	
	connectPacket := protocol.GenerateConnectPacket(connID, targetAddr)
	
	
	encData, err := c.crypto.Encrypt(connectPacket.Data)
	if err != nil {
		return 0, err
	}
	connectPacket.Data = encData
	
	
	headerBytes := protocol.SerializeHeader(connectPacket.Header)
	
	
	if c.options.EnableObfs {
		headerBytes = c.obfs.Obfuscate(headerBytes)
		connectPacket.Data = c.obfs.Obfuscate(connectPacket.Data)
	}
	
	
	if _, err := c.conn.Write(headerBytes); err != nil {
		return 0, err
	}
	
	if _, err := c.conn.Write(connectPacket.Data); err != nil {
		return 0, err
	}
	
	
	headerBuf := make([]byte, protocol.HeaderSize)
	if _, err := io.ReadFull(c.conn, headerBuf); err != nil {
		return 0, err
	}
	
	
	if c.options.EnableObfs {
		var deobfsErr error
		headerBuf, deobfsErr = c.obfs.Deobfuscate(headerBuf)
		if deobfsErr != nil {
			return 0, deobfsErr
		}
	}
	
	
	packetSize, packetType, err := protocol.ParseHeader(headerBuf)
	if err != nil {
		return 0, err
	}
	
	if packetType != protocol.PacketTypeConnectResponse {
		return 0, errors.New("получен неожиданный тип пакета")
	}
	
	
	dataBuf := make([]byte, packetSize)
	if _, err := io.ReadFull(c.conn, dataBuf); err != nil {
		return 0, err
	}
	
	
	if c.options.EnableObfs {
		var deobfsErr error
		dataBuf, deobfsErr = c.obfs.Deobfuscate(dataBuf)
		if deobfsErr != nil {
			return 0, deobfsErr
		}
	}
	
	dataBuf, err = c.crypto.Decrypt(dataBuf)
	if err != nil {
		return 0, err
	}
	
	
	success, err := protocol.ParseConnectResponse(dataBuf, connID)
	if err != nil {
		return 0, err
	}
	
	if !success {
		return 0, errors.New("сервер отклонил запрос на соединение")
	}
	
	return connID, nil
}

func (c *Client) proxyData(clientConn net.Conn, connID uint32) {
	
	clientErrCh := make(chan error, 1)
	serverErrCh := make(chan error, 1)
	
	
	go func() {
		clientErrCh <- c.proxyClientToServer(clientConn, connID)
	}()
	
	
	go func() {
		serverErrCh <- c.proxyServerToClient(clientConn, connID)
	}()
	
	
	select {
	case <-clientErrCh:
		
	case <-serverErrCh:
		
	case <-c.stop:
		
	}
	
	
	c.sendCloseRequest(connID)
}

func (c *Client) proxyClientToServer(clientConn net.Conn, connID uint32) error {
	buf := make([]byte, 4096)
	
	for {
		select {
		case <-c.stop:
			return nil
		default:
			
			clientConn.SetReadDeadline(time.Now().Add(10 * time.Second))
			
			
			n, err := clientConn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return err
			}
			
			if n > 0 {
				
				if err := c.sendDataPacket(connID, buf[:n]); err != nil {
					return err
				}
			}
		}
	}
}

func (c *Client) proxyServerToClient(clientConn net.Conn, connID uint32) error {
	
	defer func() {
		c.mu.Lock()
		
		clientConn.Close()
		
		if _, exists := c.connections[connID]; exists {
			delete(c.connections, connID)
		}
		c.mu.Unlock()
	}()
	
	
	select {
	case <-c.stop:
		return nil
	default:
		
		
		return nil
	}
}


func (c *Client) isPacketForConnection(packetType byte, connID uint32) bool {
	switch packetType {
	case protocol.PacketTypeData, protocol.PacketTypeClose, protocol.PacketTypeError:
		return true 
	case protocol.PacketTypePong:
		return false 
	default:
		return false
	}
}


func (c *Client) isControlChannel(connID uint32) bool {
	return connID == 0 
}


func (c *Client) sendDataPacket(connID uint32, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if !c.isConnected {
		return errors.New("не подключен к серверу")
	}
	
	
	dataPacket := protocol.GenerateDataPacket(connID, data)
	
	
	encData, err := c.crypto.Encrypt(dataPacket.Data)
	if err != nil {
		return err
	}
	dataPacket.Data = encData
	
	
	headerBytes := protocol.SerializeHeader(dataPacket.Header)
	
	
	if c.options.EnableObfs {
		headerBytes = c.obfs.Obfuscate(headerBytes)
		dataPacket.Data = c.obfs.Obfuscate(dataPacket.Data)
	}
	
	
	if _, err := c.conn.Write(headerBytes); err != nil {
		return err
	}
	
	if _, err := c.conn.Write(dataPacket.Data); err != nil {
		return err
	}
	
	return nil
}

func (c *Client) sendCloseRequest(connID uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if !c.isConnected {
		return nil 
	}
	
	
	closePacket := protocol.GenerateClosePacket(connID)
	
	
	encData, err := c.crypto.Encrypt(closePacket.Data)
	if err != nil {
		return err
	}
	closePacket.Data = encData
	
	
	headerBytes := protocol.SerializeHeader(closePacket.Header)
	
	
	if c.options.EnableObfs {
		headerBytes = c.obfs.Obfuscate(headerBytes)
		closePacket.Data = c.obfs.Obfuscate(closePacket.Data)
	}
	
	
	if _, err := c.conn.Write(headerBytes); err != nil {
		return err
	}
	
	if _, err := c.conn.Write(closePacket.Data); err != nil {
		return err
	}
	
	return nil
}

func (c *Client) keepAlive() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			
			if err := c.sendPing(); err != nil {
				c.logger.Errorf("Ошибка отправки ping: %v", err)
				
				if c.options.AutoReconn {
					c.logger.Info("Попытка переподключения...")
					c.reconnect()
				}
			}
		case <-c.stop:
			return
		}
	}
}

func (c *Client) sendPing() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if !c.isConnected || c.conn == nil {
		return errors.New("не подключен к серверу")
	}
	
	
	pingPacket := protocol.GeneratePingPacket()
	
	
	encData, err := c.crypto.Encrypt(pingPacket.Data)
	if err != nil {
		return err
	}
	pingPacket.Data = encData
	
	
	headerBytes := protocol.SerializeHeader(pingPacket.Header)
	
	
	if c.options.EnableObfs {
		headerBytes = c.obfs.Obfuscate(headerBytes)
		pingPacket.Data = c.obfs.Obfuscate(pingPacket.Data)
	}
	
	
	if _, err := c.conn.Write(append(headerBytes, pingPacket.Data...)); err != nil {
		c.logger.WithError(err).Warn("Ошибка отправки ping")
		c.isConnected = false
		return err
	}
	
	c.logger.Debug("Ping отправлен")
	return nil
}

func (c *Client) reconnect() {
	c.mu.Lock()
	
	if c.isConnected {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	maxRetries := 10
	retryCount := 0
	
	c.mu.Lock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	c.isConnected = false
	c.mu.Unlock()
	
	c.logger.Info("Начало процедуры переподключения")
	
	backoff := 1 * time.Second
	maxBackoff := 30 * time.Second
	
	for retryCount < maxRetries {
		select {
		case <-c.stop:
			c.logger.Info("Переподключение отменено")
			return
		default:
			c.logger.WithFields(logrus.Fields{
				"attempt": retryCount+1, 
				"delay": backoff,
			}).Info("Попытка переподключения")
			
			time.Sleep(backoff)
			
			
			serverAddr, err := net.ResolveUDPAddr("udp", c.options.ServerAddr)
			if err != nil {
				c.logger.WithError(err).Error("Ошибка разрешения адреса")
				retryCount++
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			
			conn, err := net.DialUDP("udp", nil, serverAddr)
			if err != nil {
				c.logger.WithError(err).Error("Ошибка создания соединения")
				retryCount++
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			
			c.mu.Lock()
			c.conn = conn
			c.mu.Unlock()
			
			
			if err := c.setSocketTimeout(); err != nil {
				c.logger.WithError(err).Error("Ошибка настройки таймаутов")
				c.mu.Lock()
				c.conn.Close()
				c.conn = nil
				c.mu.Unlock()
				retryCount++
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			
			
			if err := c.handshake(); err != nil {
				c.logger.WithError(err).Error("Ошибка рукопожатия")
				c.mu.Lock()
				c.conn.Close()
				c.conn = nil
				c.mu.Unlock()
				retryCount++
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}
			
			
			c.mu.Lock()
			c.isConnected = true
			c.mu.Unlock()
			
			c.logger.Info("Переподключение выполнено успешно")
			
			
			go c.readLoop()
			go c.pingLoop()
			
			
			if c.options.UseTUN && c.tunIface != nil {
				if err := c.configureTUN(); err != nil {
					c.logger.WithError(err).Warn("Ошибка переконфигурации TUN")
				}
			}
			
			return
		}
	}
	
	c.logger.Error("Исчерпаны попытки переподключения")
}

func (c *Client) connectVPN() error {
	
	return nil
}


func (c *Client) setupTUN() error {
	c.logger.Info("Настройка TUN-интерфейса")
	
	config := water.Config{
		DeviceType: water.TUN,
	}
	
	
	if c.options.TUNName != "" {
		config.Name = c.options.TUNName
	}
	
	
	iface, err := water.New(config)
	if err != nil {
		return fmt.Errorf("ошибка создания TUN-интерфейса: %v", err)
	}
	c.tunIface = iface
	
	
	if err := c.configureTUN(); err != nil {
		c.tunIface.Close()
		return err
	}
	
	
	go c.processTUNPackets()
	
	c.logger.WithFields(logrus.Fields{
		"name": c.tunIface.Name(),
		"local_ip": c.options.TUNLocalIP,
		"remote_ip": c.options.TUNRemoteIP,
	}).Info("TUN-интерфейс успешно настроен")
	
	return nil
}


func (c *Client) configureTUN() error {
	return c.configureTUNWithParams(c.options.TUNLocalIP, c.options.TUNRemoteIP, 1500)
}


func (c *Client) configureTUNWithParams(localIP, remoteIP string, mtu int) error {
	var cmd *exec.Cmd
	ifaceName := c.tunIface.Name()
	
	
	switch runtime.GOOS {
	case "linux":
		
		cmd = exec.Command("ip", "link", "set", "dev", ifaceName, "mtu", strconv.Itoa(mtu))
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ошибка установки MTU: %v", err)
		}
		
		
		cmd = exec.Command("ip", "addr", "add", localIP+"/30", "dev", ifaceName)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ошибка установки IP: %v", err)
		}
		
		
		cmd = exec.Command("ip", "link", "set", "dev", ifaceName, "up")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ошибка включения интерфейса: %v", err)
		}
		
		
		if c.options.TUNRouteAll {
			
			cmd = exec.Command("ip", "route", "add", "0.0.0.0/1", "via", remoteIP)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("ошибка добавления маршрута 0.0.0.0/1: %v", err)
			}
			
			cmd = exec.Command("ip", "route", "add", "128.0.0.0/1", "via", remoteIP)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("ошибка добавления маршрута 128.0.0.0/1: %v", err)
			}
		}
		
	case "darwin":
		
		cmd = exec.Command("ifconfig", ifaceName, localIP, remoteIP, "up")
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ошибка настройки интерфейса: %v", err)
		}
		
		if c.options.TUNRouteAll {
			cmd = exec.Command("route", "add", "0.0.0.0/1", remoteIP)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("ошибка добавления маршрута 0.0.0.0/1: %v", err)
			}
			
			cmd = exec.Command("route", "add", "128.0.0.0/1", remoteIP)
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("ошибка добавления маршрута 128.0.0.0/1: %v", err)
			}
		}
		
	case "windows":
		
		
		return fmt.Errorf("настройка TUN для Windows пока не реализована")
		
	default:
		return fmt.Errorf("неподдерживаемая ОС: %s", runtime.GOOS)
	}
	
	
	_, ipNet, err := net.ParseCIDR(localIP + "/30")
	if err != nil {
		return fmt.Errorf("ошибка при парсинге CIDR: %v", err)
	}
	c.tunCidr = ipNet
	
	
	c.options.TUNLocalIP = localIP
	c.options.TUNRemoteIP = remoteIP
	
	return nil
}


func (c *Client) processTUNPackets() {
	buffer := make([]byte, 2048)
	
	c.logger.Info("Запуск обработчика TUN-пакетов")
	
	for {
		
		select {
		case <-c.stop:
			c.logger.Info("Остановка обработчика TUN-пакетов")
			return
		default:
		}
		
		
		n, err := c.tunIface.Read(buffer)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				c.logger.WithError(err).Error("Ошибка чтения из TUN-интерфейса")
			}
			
			
			if !c.options.AutoReconn {
				c.logger.WithError(err).Error("Ошибка чтения из TUN-интерфейса, автопереподключение отключено")
				return
			}
			
			
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		packet := buffer[:n]
		
		
		if len(packet) < 20 {
			c.logger.WithField("size", len(packet)).Debug("Получен слишком короткий пакет")
			continue
		}
		
		
		version := packet[0] >> 4
		
		
		if version != 4 {
			
			if version == 6 {
				c.logger.Debug("Пропуск IPv6 пакета (не поддерживается)")
			} else {
				c.logger.WithField("version", int(version)).Warn("Неизвестная версия IP")
			}
			continue
		}
		
		
		if err := c.sendTUNPacket(packet); err != nil {
			c.logger.WithError(err).Error("Ошибка отправки TUN-пакета")
		}
	}
}


func (c *Client) sendTUNPacket(packet []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	
	if !c.isConnected || c.conn == nil {
		return errors.New("нет активного соединения с сервером")
	}
	
	
	if len(packet) < 20 {
		return errors.New("слишком короткий пакет для отправки")
	}
	
	
	version := packet[0] >> 4
	if version != 4 && version != 6 {
		return fmt.Errorf("неподдерживаемая версия IP: %d", version)
	}
	
	
	var processedPacket []byte
	
	
	verbose := false
	
	
	if c.options.EnableObfs {
		processedPacket = c.obfs.Obfuscate(packet)
		
		
		if c.dataPreprocessor != nil {
			var modified bool
			processedPacket, modified = c.dataPreprocessor(processedPacket)
			if !modified && verbose {
				c.logger.Debug("Препроцессор пропустил пакет без изменений")
			}
		}
	} else {
		
		processedPacket = packet
	}
	
	
	encryptedData, err := c.crypto.Encrypt(processedPacket)
	if err != nil {
		return fmt.Errorf("ошибка шифрования: %v", err)
	}
	
	
	headerBytes := protocol.GenerateHeader(uint32(len(encryptedData)), protocol.PacketTypeData)
	
	
	if c.options.EnableObfs {
		headerBytes = c.obfs.Obfuscate(headerBytes)
	}
	
	
	combinedPacket := append(headerBytes, encryptedData...)
	
	
	if c.options.NaturalTiming {
		
		jitter := time.Duration(rand.Intn(5)) * time.Millisecond
		time.Sleep(jitter)
	}
	
	
	c.stats.outPackets++
	c.stats.outBytes += uint64(len(combinedPacket))
	
	
	_, err = c.conn.Write(combinedPacket)
	if err != nil {
		
		c.isConnected = false
		
		
		if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed") {
			return fmt.Errorf("соединение закрыто: %v", err)
		}
		
		return fmt.Errorf("ошибка отправки TUN-пакета: %v", err)
	}
	
	
	c.lastActivity = time.Now()
	
	return nil
}


func (c *Client) handleCloseAck(connID uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.logger.WithField("connID", connID).Debug("Получено подтверждение закрытия соединения")

	
	delete(c.connections, connID)
	return nil
}


func (c *Client) handleConnectResponse(connID uint32, status uint32) error {
	c.logger.WithFields(logrus.Fields{
		"connID": connID, 
		"status": status,
	}).Debug("Получен ответ на запрос соединения")

	
	
	return nil
}


func (c *Client) handleDataPacket(connID uint32, data []byte) error {
	c.mu.Lock()
	_, exists := c.connections[connID]
	if !exists {
		c.mu.Unlock()
		return fmt.Errorf("соединение %d не найдено", connID)
	}
	
	
	c.connections[connID] = time.Now()
	
	
	if connID == TUNConnID {
		c.mu.Unlock()
		
		if c.tunIface == nil {
			return errors.New("TUN-интерфейс не настроен")
		}
		
		
		if len(data) < 20 {
			return errors.New("некорректный IP-пакет")
		}
		
		_, err := c.tunIface.Write(data)
		if err != nil {
			return fmt.Errorf("ошибка записи в TUN: %v", err)
		}
	} else {
		
		sockConn, exists := c.sockConnections[connID]
		c.mu.Unlock()
		
		if !exists {
			return fmt.Errorf("SOCKS соединение %d не найдено", connID)
		}
		
		if sockConn.conn == nil {
			return fmt.Errorf("SOCKS соединение %d закрыто", connID)
		}
		
		
		sockConn.lastSeen = time.Now()
		
		
		n, err := sockConn.conn.Write(data)
		if err != nil {
			c.logger.WithFields(logrus.Fields{
				"connID": connID,
				"error": err.Error(),
			}).Error("Ошибка записи в SOCKS соединение")
			
			
			sockConn.conn.Close()
			
			c.mu.Lock()
			delete(c.sockConnections, connID)
			delete(c.connections, connID)
			c.mu.Unlock()
			
			return fmt.Errorf("ошибка записи в SOCKS: %v", err)
		}
		
		if n != len(data) {
			c.logger.WithFields(logrus.Fields{
				"connID": connID,
				"written": n,
				"expected": len(data),
			}).Warn("Не все данные были записаны в SOCKS соединение")
		}
	}
	
	return nil
}


func (c *Client) handleErrorPacket(connID uint32, errorCode byte) error {
	errMsg := "неизвестная ошибка"
	
	
	switch errorCode {
	case protocol.ErrorConnectionFailed:
		errMsg = "ошибка подключения к целевому хосту"
	case protocol.ErrorConnectionNotFound:
		errMsg = "соединение не найдено"
	case protocol.ErrorWriteFailed:
		errMsg = "ошибка записи данных"
	case protocol.ErrorInvalidPacket:
		errMsg = "недействительный пакет"
	case protocol.ErrorTUNFailed:
		errMsg = "ошибка настройки TUN"
	}
	
	c.logger.WithFields(logrus.Fields{
		"connID": connID,
		"errorCode": errorCode,
		"error": errMsg,
	}).Warn("Получена ошибка от сервера")
	
	
	c.mu.Lock()
	delete(c.connections, connID)
	c.mu.Unlock()
	
	return fmt.Errorf("ошибка от сервера: %s (код %d)", errMsg, errorCode)
}


func (c *Client) handleTUNConfig(data []byte) error {
	if !c.options.UseTUN {
		c.logger.Warn("Получен TUN-конфиг, но TUN не включен")
		return errors.New("TUN не включен")
	}

	localIP, remoteIP, mtu, err := protocol.ParseTUNConfigPacket(data)
	if err != nil {
		c.logger.WithError(err).Error("Ошибка разбора TUN-конфига")
		return err
	}

	c.logger.WithFields(logrus.Fields{
		"localIP": localIP,
		"remoteIP": remoteIP,
		"mtu": mtu,
	}).Info("Получена конфигурация TUN")

	
	c.options.TUNLocalIP = localIP
	c.options.TUNRemoteIP = remoteIP
	
	
	if c.tunIface == nil {
		if err := c.setupTUN(); err != nil {
			c.logger.WithError(err).Error("Ошибка настройки TUN-интерфейса")
			return err
		}
	} else {
		
		if err := c.configureTUNWithParams(localIP, remoteIP, int(mtu)); err != nil {
			c.logger.WithError(err).Error("Ошибка конфигурации TUN")
			return err
		}
	}

	c.logger.Info("TUN интерфейс успешно настроен")
	return nil
}


func (c *Client) pingLoop() {
	c.logger.Debug("Запуск цикла пинга")
	defer c.logger.Debug("Цикл пинга завершен")

	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.sendPing(); err != nil {
				c.logger.WithError(err).Warn("Ошибка отправки ping")
				if c.options.AutoReconn {
					go c.reconnect()
				}
				return
			}
		case <-c.stop:
			return
		}
	}
}


func (c *Client) SetupSignalHandler() {
	c.logger.Info("Настройка обработчика сигналов")
	
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		sig := <-signalCh
		c.logger.WithField("signal", sig.String()).Info("Получен сигнал завершения работы")
		c.Stop()
	}()
}


func (c *Client) SetLogger(logger *logrus.Logger) {
	if logger != nil {
		c.logger = logger
	}
}


func (c *Client) SetLogLevel(level string) error {
	if c.logger == nil {
		c.logger = logrus.New()
	}
	
	switch strings.ToLower(level) {
	case "debug":
		c.logger.SetLevel(logrus.DebugLevel)
	case "info":
		c.logger.SetLevel(logrus.InfoLevel)
	case "warn", "warning":
		c.logger.SetLevel(logrus.WarnLevel)
	case "error":
		c.logger.SetLevel(logrus.ErrorLevel)
	default:
		return fmt.Errorf("неизвестный уровень логирования: %s", level)
	}
	
	return nil
}


func (c *Client) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isConnected
}


func (c *Client) GetStats() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	stats := map[string]interface{}{
		"connected":         c.isConnected,
		"active_connections": len(c.connections),
		"tun_enabled":       c.options.UseTUN,
		"obfuscation_enabled": c.options.EnableObfs,
	}
	
	if c.options.UseTUN && c.tunIface != nil {
		stats["tun_name"] = c.tunIface.Name()
		stats["tun_local_ip"] = c.options.TUNLocalIP
		stats["tun_remote_ip"] = c.options.TUNRemoteIP
	}
	
	return stats
}


func (c *Client) readLoop() {
	c.logger.Debug("Запуск цикла чтения")
	defer c.logger.Debug("Цикл чтения завершен")

	buffer := make([]byte, 4096)

	for {
		
		select {
		case <-c.stop:
			c.logger.Debug("Получен сигнал остановки, завершаем цикл чтения")
			return
		default:
		}

		
		if err := c.conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
			c.logger.WithError(err).Error("Ошибка установки таймаута чтения")
			if c.options.AutoReconn {
				go c.reconnect()
			}
			return
		}

		
		n, err := c.conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				c.logger.Warn("Таймаут чтения из соединения")
				
				if err := c.sendPing(); err != nil {
					c.logger.WithError(err).Error("Ошибка проверки связи")
					if c.options.AutoReconn {
						go c.reconnect()
					}
				}
				continue
			}

			c.logger.WithError(err).Error("Ошибка чтения из соединения")
			if c.options.AutoReconn {
				go c.reconnect()
			}
			return
		}

		
		if n < protocol.HeaderSize {
			c.logger.WithField("size", n).Error("Получен слишком короткий пакет")
			continue
		}

		receivedData := buffer[:n]

		
		if c.options.EnableObfs {
			
			var headerErr, dataErr error
			headerBytes, headerErr := c.obfs.Deobfuscate(receivedData[:protocol.HeaderSize])
			if headerErr != nil {
				c.logger.WithError(headerErr).Error("Ошибка деобфускации заголовка")
				continue
			}
			
			var dataBytes []byte
			if len(receivedData) > protocol.HeaderSize {
				dataBytes, dataErr = c.obfs.Deobfuscate(receivedData[protocol.HeaderSize:])
				if dataErr != nil {
					c.logger.WithError(dataErr).Error("Ошибка деобфускации данных")
					continue
				}
				receivedData = append(headerBytes, dataBytes...)
			} else {
				receivedData = headerBytes
			}
			
			
			if len(receivedData) < protocol.HeaderSize {
				c.logger.WithField("size", len(receivedData)).Error("Недопустимый размер пакета после деобфускации")
				continue
			}
		}

		
		packetSize, packetType, parseErr := protocol.ParseHeader(receivedData[:protocol.HeaderSize])
		if parseErr != nil {
			c.logger.WithError(parseErr).Error("Ошибка разбора заголовка пакета")
			continue
		}
		
		
		if len(receivedData) < protocol.HeaderSize+int(packetSize) {
			c.logger.WithFields(logrus.Fields{
				"expected": protocol.HeaderSize+int(packetSize),
				"actual": len(receivedData),
			}).Error("Неполный пакет")
			continue
		}
		
		
		packet := &protocol.Packet{
			Header: &protocol.PacketHeader{
				PacketType: packetType,
				PacketSize: packetSize,
			},
			Data: receivedData[protocol.HeaderSize:protocol.HeaderSize+int(packetSize)],
		}

		
		if err := c.processPacket(*packet); err != nil {
			c.logger.WithError(err).Error("Ошибка обработки пакета")
		}
	}
}


func (c *Client) processPacket(packet protocol.Packet) error {
	
	var data []byte
	var err error
	if len(packet.Data) > 0 {
		data, err = c.crypto.Decrypt(packet.Data)
		if err != nil {
			return fmt.Errorf("ошибка расшифровки данных: %w", err)
		}
	}

	
	switch packet.Header.PacketType {
	case protocol.PacketTypePong:
		
		c.lastPing = time.Now()
		c.logger.Debug("Получен pong от сервера")

	case protocol.PacketTypeData:
		
		if c.tunIface != nil {
			_, err := c.tunIface.Write(data)
			if err != nil {
				return fmt.Errorf("ошибка записи в TUN: %w", err)
			}
		} else {
			return errors.New("получены данные для TUN, но TUN не настроен")
		}

	case protocol.PacketTypeConnectResponse:
		connID := binary.BigEndian.Uint32(data[0:4])
		status := binary.BigEndian.Uint32(data[4:8])
		return c.handleConnectResponse(connID, status)

	case protocol.PacketTypeCloseACK:
		connID := binary.BigEndian.Uint32(data[0:4])
		return c.handleCloseAck(connID)

	case protocol.PacketTypeTUNConfig:
		if err := c.handleTUNConfig(data); err != nil {
			return fmt.Errorf("ошибка обработки конфигурации TUN: %w", err)
		}

	case protocol.PacketTypeTUNIP:
		if err := c.handleTUNIP(data); err != nil {
			return fmt.Errorf("ошибка обработки IP для TUN: %w", err)
		}

	case protocol.PacketTypeError:
		errorCode := data[0]
		connID := binary.BigEndian.Uint32(data[1:5])
		return c.handleErrorPacket(connID, errorCode)

	default:
		return fmt.Errorf("неизвестный тип пакета: %d", packet.Header.PacketType)
	}

	return nil
}


func (c *Client) handleTUNIP(data []byte) error {
	if !c.options.UseTUN {
		c.logger.Warn("Получен TUN-IP, но TUN не включен")
		return errors.New("TUN не включен")
	}

	clientIP, serverIP, routes, err := protocol.ParseTUNIPPacket(data)
	if err != nil {
		c.logger.WithError(err).Error("Ошибка разбора TUN-IP")
		return err
	}

	c.logger.WithFields(logrus.Fields{
		"clientIP": clientIP,
		"serverIP": serverIP,
		"routes":   routes,
	}).Info("Получены IP-адреса для TUN")

	
	if err := c.configureRoutes(routes); err != nil {
		c.logger.WithError(err).Error("Ошибка настройки маршрутов")
		return err
	}

	c.logger.Info("Маршруты успешно настроены")
	return nil
}


func (c *Client) configureRoutes(routes []string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("настройка маршрутов поддерживается только для Linux")
	}

	for _, route := range routes {
		cmd := exec.Command("ip", "route", "add", route, "via", c.options.TUNRemoteIP)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ошибка добавления маршрута %s: %v", route, err)
		}
	}

	
	if c.options.TUNRouteAll {
		cmd := exec.Command("ip", "route", "add", "default", "via", c.options.TUNRemoteIP)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("ошибка добавления маршрута по умолчанию: %v", err)
		}
	}

	return nil
}


func (c *Client) handshake() error {
	
	handshakePacket := protocol.GenerateHandshake()
	
	
	if c.options.EnableObfs {
		handshakePacket = c.obfs.Obfuscate(handshakePacket)
	}
	
	
	_, err := c.conn.Write(handshakePacket)
	if err != nil {
		return fmt.Errorf("ошибка отправки рукопожатия: %v", err)
	}
	
	
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	
	
	response := make([]byte, protocol.HandshakeResponseSize)
	_, err = io.ReadFull(c.conn, response)
	if err != nil {
		return fmt.Errorf("ошибка чтения ответа на рукопожатие: %v", err)
	}
	
	
	c.conn.SetReadDeadline(time.Time{})
	
	
	if c.options.EnableObfs {
		var deobfErr error
		response, deobfErr = c.obfs.Deobfuscate(response)
		if deobfErr != nil {
			return fmt.Errorf("ошибка деобфускации ответа: %v", deobfErr)
		}
	}
	
	
	if !protocol.ValidateHandshakeResponse(response) {
		return errors.New("недействительный ответ на рукопожатие")
	}
	
	c.logger.Debug("Рукопожатие успешно выполнено")
	return nil
}


func (c *Client) setSocketTimeout() error {
	
	
	if udpConn, ok := c.conn.(*net.UDPConn); ok {
		if err := udpConn.SetReadBuffer(65536); err != nil {
			return fmt.Errorf("ошибка установки размера буфера чтения: %v", err)
		}
		
		if err := udpConn.SetWriteBuffer(65536); err != nil {
			return fmt.Errorf("ошибка установки размера буфера записи: %v", err)
		}
	}
	
	return nil
}


func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.logger.WithField("address", c.options.ServerAddr).Info("Подключение к серверу")

	
	if c.isConnected && c.conn != nil {
		c.logger.Info("Уже подключен к серверу")
		return nil
	}

	
	serverAddr, err := net.ResolveUDPAddr("udp", c.options.ServerAddr)
	if err != nil {
		return fmt.Errorf("ошибка разрешения адреса сервера: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return fmt.Errorf("ошибка соединения с сервером: %w", err)
	}
	c.conn = conn

	
	if err := c.setSocketTimeout(); err != nil {
		c.conn.Close()
		c.conn = nil
		return fmt.Errorf("ошибка настройки таймаутов: %w", err)
	}

	
	if c.options.EnableObfs {
		c.enhanceObfuscation()
	}

	
	if c.options.MimicHTTPS || c.options.MimicDNS || c.options.MimicWebRTC {
		c.enableAntiProbe()
	}

	
	if err := c.handshake(); err != nil {
		c.conn.Close()
		c.conn = nil
		return fmt.Errorf("ошибка рукопожатия: %w", err)
	}

	
	if c.options.UseTUN {
		if err := c.setupTUN(); err != nil {
			c.conn.Close()
			c.conn = nil
			return fmt.Errorf("ошибка настройки TUN-интерфейса: %w", err)
		}
	}

	
	c.isConnected = true
	c.logger.Info("Успешное подключение к серверу")

	
	go c.readLoop()
	go c.pingLoop()

	return nil
}


func (c *Client) processTUNDataPacket(packet *protocol.Packet) error {
	if !c.options.UseTUN || c.tunIface == nil {
		c.logger.Warn("Получен TUN-пакет, но TUN интерфейс не настроен")
		return nil
	}

	if len(packet.Data) < 4 {
		return errors.New("слишком короткий TUN-пакет")
	}

	
	_, err := c.tunIface.Write(packet.Data)
	if err != nil {
		return fmt.Errorf("ошибка записи в TUN: %v", err)
	}
	
	return nil
}


func (c *Client) enhanceObfuscation() error {
	c.logger.Info("Настройка улучшенной обфускации трафика")
	
	
	
	

	if c.obfs != nil {
		c.obfs.SetFragmentation(true)
		c.obfs.SetFragmentSize(200 + int(time.Now().UnixNano()%300))
	}
	

	
	
	if c.options.MimicHTTPS {
		
		domains := []string{
			"www.google.com",
			"github.com",
			"cloudflare.com",
			"microsoft.com",
			"amazon.com",
			"netflix.com",
			"apple.com",
		}
		
		
		selectedDomain := domains[int(time.Now().UnixNano()%int64(len(domains)))]
		c.logger.WithField("domain", selectedDomain).Debug("Имитация HTTPS трафика")
		
		
		c.dataPreprocessor = func(data []byte) ([]byte, bool) {
			
			if int(time.Now().UnixNano()%100) < 5 && len(data) > 100 {
				
				tlsHeader := generateFakeTLSClientHello(selectedDomain)
				
				result := append(tlsHeader, data...)
				return result, true
			}
			return data, false
		}
	}
	
	
	if c.options.MimicDNS {
		c.logger.Debug("Имитация DNS трафика")
		
		
		go func() {
			for {
				select {
				case <-c.stop:
					return
				case <-time.After(time.Duration(30+int(time.Now().UnixNano()%60)) * time.Second):
					
					fakeDNS := generateFakeDNSRequest()
					c.mu.Lock()
					if c.conn != nil && c.isConnected {
						
						c.conn.Write(fakeDNS)
					}
					c.mu.Unlock()
				}
			}
		}()
	}
	
	
	if c.options.MimicWebRTC {
		c.logger.Debug("Имитация WebRTC трафика")
		
		
		
		preProcessor := c.dataPreprocessor
		c.dataPreprocessor = func(data []byte) ([]byte, bool) {
			
			if preProcessor != nil {
				data, _ = preProcessor(data)
			}
			
			
			if int(time.Now().UnixNano()%100) < 10 && len(data) > 50 {
				
				webRTCHeader := generateFakeWebRTCHeader()
				result := append(webRTCHeader, data...)
				return result, true
			}
			return data, false
		}
	}
	
	return nil
}


func (c *Client) enableAntiProbe() {
	c.logger.Info("Активация защиты от активного зондирования")
	
	
	synScanDetector := func() {
		
		go func() {
			for {
				select {
				case <-c.stop:
					return
				case <-time.After(1 * time.Second):
					c.mu.Lock()
					count := c.recentSYNCount
					c.recentSYNCount = 0
					c.mu.Unlock()
					
					
					if count > 10 {
						c.logger.WithField("count", count).Warn("Обнаружено возможное SYN-сканирование")
						
					}
				}
			}
		}()
	}
	
	
	synScanDetector()
}


func (c *Client) rotateObfuscationPattern() {
	if !c.options.EnableObfs && !c.options.MimicHTTPS && !c.options.MimicDNS && !c.options.MimicWebRTC {
		return
	}
	
	c.logger.Info("Запуск ротации паттернов обфускации")
	
	go func() {
		for {
			select {
			case <-c.stop:
				return
			case <-time.After(time.Duration(30+int(time.Now().UnixNano()%30)) * time.Minute):
				c.logger.Debug("Ротация ключей и параметров обфускации")
				
				
				

				c.mu.Lock()
				if c.obfs != nil {
					c.obfs.RegenerateKeys()
					c.obfs.SetFragmentSize(200 + int(time.Now().UnixNano()%300))
				}
				if c.crypto != nil {
					c.crypto.RotateKeys()
				}
				c.mu.Unlock()
				

			}
		}
	}()
}


func generateFakeTLSClientHello(serverName string) []byte {
	
	tlsHeader := []byte{
		0x16,                   
		0x03, 0x01,             
		0x00, 0x00,             
	}
	
	
	handshakeHeader := []byte{
		0x01,                   
		0x00, 0x00, 0x00,       
		0x03, 0x03,             
	}
	
	
	random := make([]byte, 32)
	crand.Read(random)
	
	
	sessionIDLength := byte(int(time.Now().UnixNano()) % 32)
	sessionID := make([]byte, sessionIDLength)
	crand.Read(sessionID)
	
	
	cipherSuites := []byte{
		0x00, 0x06,             
		0xc0, 0x2b,             
		0xc0, 0x2f,             
		0x00, 0x9e,             
	}
	
	
	compressionMethods := []byte{
		0x01,                   
		0x00,                   
	}
	
	
	extensions := []byte{
		0x00, 0x00,             
	}
	
	
	sni := []byte{
		0x00, 0x00,             
		0x00, 0x00,             
		0x00, 0x00,             
		0x00,                   
		0x00, 0x00,             
	}
	
	
	serverNameBytes := []byte(serverName)
	sni = append(sni, serverNameBytes...)
	
	
	binary.BigEndian.PutUint16(sni[7:9], uint16(len(serverNameBytes)))
	
	
	binary.BigEndian.PutUint16(sni[5:7], uint16(len(serverNameBytes)+3))
	
	
	binary.BigEndian.PutUint16(sni[3:5], uint16(len(serverNameBytes)+5))
	
	
	extensions = append(extensions, sni...)
	
	
	binary.BigEndian.PutUint16(extensions[0:2], uint16(len(extensions)-2))
	
	
	clientHello := append(handshakeHeader, random...)
	clientHello = append(clientHello, sessionIDLength)
	clientHello = append(clientHello, sessionID...)
	clientHello = append(clientHello, cipherSuites...)
	clientHello = append(clientHello, compressionMethods...)
	clientHello = append(clientHello, extensions...)
	
	
	binary.BigEndian.PutUint32(clientHello[1:5], uint32(len(clientHello)-5))
	
	
	tlsPacket := append(tlsHeader, clientHello...)
	
	
	binary.BigEndian.PutUint16(tlsPacket[3:5], uint16(len(clientHello)))
	
	return tlsPacket
}


func generateFakeDNSRequest() []byte {
	
	domains := []string{
		"www.google.com",
		"github.com",
		"microsoft.com",
		"cloudflare.com",
		"apple.com",
		"amazon.com",
		"facebook.com",
	}
	
	domain := domains[int(time.Now().UnixNano()%int64(len(domains)))]
	
	
	
	id := make([]byte, 2)
	crand.Read(id)
	
	header := []byte{
		id[0], id[1],        
		0x01, 0x00,          
		0x00, 0x01,          
		0x00, 0x00,          
		0x00, 0x00,          
		0x00, 0x00,          
	}
	
	
	request := []byte{}
	
	
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		request = append(request, byte(len(part)))
		request = append(request, []byte(part)...)
	}
	
	
	request = append(request, 0x00)
	
	
	request = append(request, 0x00, 0x01)
	
	
	request = append(request, 0x00, 0x01)
	
	
	dnsPacket := append(header, request...)
	
	return dnsPacket
}


func generateFakeWebRTCHeader() []byte {
	
	stunHeader := []byte{
		0x00, 0x01,             
		0x00, 0x08,             
		0x21, 0x12, 0xA4, 0x42, 
	}
	
	
	transactionID := make([]byte, 12)
	crand.Read(transactionID)
	
	
	stunHeader = append(stunHeader, transactionID...)
	
	return stunHeader
} 