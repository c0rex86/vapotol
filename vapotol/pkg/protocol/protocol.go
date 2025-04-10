
package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	
	Version = "1.0.0"
	
	
	HandshakeSize         = 64
	HandshakeResponseSize = 64
	HeaderSize            = 16

	
	PacketTypeHandshake       = 0x01
	PacketTypeHandshakeResp   = 0x02
	PacketTypeData            = 0x03
	PacketTypeConnect         = 0x04
	PacketTypeConnectResponse = 0x05
	PacketTypeClose           = 0x06
	PacketTypeAck             = 0x07
	PacketTypePing            = 0x08
	PacketTypePong            = 0x09
	PacketTypeError           = 0x0A
	PacketTypeConnectOK       = 0x0B
	PacketTypeCloseACK        = 0x0C
	PacketTypeTUNConfig       = 0x0D 
	PacketTypeTUNIP           = 0x0E 
	PacketTypeTUNData         = 0x0F 
	
	
	ErrorConnectionFailed    = 0x01
	ErrorConnectionNotFound  = 0x02
	ErrorWriteFailed         = 0x03
	ErrorInvalidPacket       = 0x04
	ErrorTUNFailed           = 0x05 
	
	
	TargetTypeDomain        = 0x01
	TargetTypeIPv4          = 0x02
	TargetTypeIPv6          = 0x03
)


var vapotolSignature = []byte{0x56, 0x41, 0x50, 0x4F, 0x54, 0x4F, 0x4C} 


type Packet struct {
	Header *PacketHeader
	Data   []byte
}


type PacketHeader struct {
	PacketType byte
	PacketSize uint32
}


func GenerateHandshake() []byte {
	
	handshake := make([]byte, HandshakeSize)

	
	copy(handshake, vapotolSignature)

	
	handshake[7] = 0x01

	
	handshake[8] = PacketTypeHandshake

	
	_, err := rand.Read(handshake[9:])
	if err != nil {
		
		for i := 9; i < HandshakeSize; i++ {
			handshake[i] = 0
		}
	}

	return handshake
}


func ValidateHandshake(handshake []byte) bool {
	if len(handshake) < 9 {
		return false
	}

	
	if !bytes.Equal(handshake[:7], vapotolSignature) {
		return false
	}

	
	if handshake[7] != 0x01 {
		return false
	}

	
	if handshake[8] != PacketTypeHandshake {
		return false
	}

	return true
}


func GenerateHandshakeResponse() []byte {
	
	response := make([]byte, HandshakeResponseSize)

	
	copy(response, vapotolSignature)

	
	response[7] = 0x01

	
	response[8] = PacketTypeHandshakeResp

	
	response[9] = 0x03 

	
	_, err := rand.Read(response[10:])
	if err != nil {
		
		for i := 10; i < HandshakeResponseSize; i++ {
			response[i] = 0
		}
	}

	return response
}


func ValidateHandshakeResponse(response []byte) bool {
	if len(response) < 9 {
		return false
	}

	
	if !bytes.Equal(response[:7], vapotolSignature) {
		return false
	}

	
	if response[7] != 0x01 {
		return false
	}

	
	if response[8] != PacketTypeHandshakeResp {
		return false
	}

	return true
}


func GenerateHeader(packetSize uint32, packetType byte) []byte {
	
	header := make([]byte, HeaderSize)

	
	copy(header, vapotolSignature[:4]) 

	
	header[4] = packetType

	
	binary.BigEndian.PutUint32(header[5:9], packetSize)

	
	timestamp := uint32(time.Now().Unix())
	binary.BigEndian.PutUint32(header[9:13], timestamp)

	
	_, err := rand.Read(header[13:])
	if err != nil {
		
		for i := 13; i < HeaderSize; i++ {
			header[i] = 0
		}
	}

	return header
}


func ParseHeader(header []byte) (uint32, byte, error) {
	if len(header) < HeaderSize {
		return 0, 0, errors.New("заголовок слишком короткий")
	}

	
	if !bytes.Equal(header[:4], vapotolSignature[:4]) {
		return 0, 0, errors.New("недействительная сигнатура заголовка")
	}

	
	packetType := header[4]

	
	packetSize := binary.BigEndian.Uint32(header[5:9])

	return packetSize, packetType, nil
}


func GenerateConnectionID() uint32 {
	
	idBytes := make([]byte, 4)
	rand.Read(idBytes)
	return binary.BigEndian.Uint32(idBytes)
}


func GenerateConnectPacket(connID uint32, target string) *Packet {
	
	data := make([]byte, 4+1+len(target))
	
	
	binary.BigEndian.PutUint32(data[:4], connID)
	
	
	data[4] = byte(len(target))
	
	
	copy(data[5:], []byte(target))
	
	
	return &Packet{
		Header: &PacketHeader{
			PacketType: PacketTypeConnect,
			PacketSize: uint32(len(data)),
		},
		Data: data,
	}
}


func ParseConnectResponse(data []byte, expectedConnID uint32) (bool, error) {
	if len(data) < 8 {
		return false, errors.New("данные слишком короткие")
	}

	
	connID := binary.BigEndian.Uint32(data[:4])

	
	if connID != expectedConnID {
		return false, fmt.Errorf("несоответствие ID соединения: ожидалось %d, получено %d", expectedConnID, connID)
	}

	
	status := binary.BigEndian.Uint32(data[4:8])

	
	if status != 0 {
		return false, fmt.Errorf("сервер отклонил соединение с кодом %d", status)
	}

	return true, nil
}


func GenerateDataPacket(connID uint32, data []byte) *Packet {
	
	packetData := make([]byte, 4+len(data))
	
	
	binary.BigEndian.PutUint32(packetData[:4], connID)
	
	
	copy(packetData[4:], data)
	
	
	return &Packet{
		Header: &PacketHeader{
			PacketType: PacketTypeData,
			PacketSize: uint32(len(packetData)),
		},
		Data: packetData,
	}
}


func GenerateClosePacket(connID uint32) *Packet {
	
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, connID)
	
	
	return &Packet{
		Header: &PacketHeader{
			PacketType: PacketTypeClose,
			PacketSize: 4,
		},
		Data: data,
	}
}


func GenerateAckPacket(connID uint32) *Packet {
	
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, connID)
	
	
	return &Packet{
		Header: &PacketHeader{
			PacketType: PacketTypeAck,
			PacketSize: 4,
		},
		Data: data,
	}
}


func GeneratePingPacket() *Packet {
	
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(time.Now().UnixNano()))
	
	
	return &Packet{
		Header: &PacketHeader{
			PacketType: PacketTypePing,
			PacketSize: 8,
		},
		Data: data,
	}
}


func GeneratePongPacket(pingData []byte) *Packet {
	
	data := make([]byte, len(pingData))
	copy(data, pingData)
	
	
	return &Packet{
		Header: &PacketHeader{
			PacketType: PacketTypePong,
			PacketSize: 8,
		},
		Data: data,
	}
}


func ContainsVapotolMarker(data []byte) bool {
	
	
	marker := []byte("X-Vapotol-Key:")
	return bytes.Contains(data, marker)
}


func GenerateHTTPCamouflagedResponse() []byte {
	
	response := "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.18.0\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Cache-Control: no-cache\r\n" +
		"X-Vapotol-Ack: " + generateRandomHexString(32) + "\r\n" +
		"Connection: keep-alive\r\n" +
		"Content-Length: 0\r\n\r\n"

	return []byte(response)
}


func IsVapotolOverDNS(data []byte) bool {
	
	
	if len(data) < 12 {
		return false
	}

	
	marker := []byte("vpntunnel")
	return bytes.Contains(data, marker)
}


func ExtractVapotolFromDNS(data []byte) ([]byte, error) {
	
	
	
	if !IsVapotolOverDNS(data) {
		return nil, errors.New("не является VAPOtol-запросом через DNS")
	}

	
	if len(data) <= 12 {
		return nil, errors.New("данные DNS слишком короткие")
	}

	return data[12:], nil
}


func PackVapotolIntoDNS(responseData []byte, requestData []byte) []byte {
	
	
	
	if len(requestData) < 12 {
		
		return GenerateFakeDNSResponse(requestData)
	}

	
	response := make([]byte, 12+len(responseData))
	copy(response[:2], requestData[:2]) 
	response[2] = 0x81                  
	response[3] = 0x80                  
	response[4] = 0x00                  
	response[5] = 0x01                  
	response[6] = 0x00                  
	response[7] = 0x01                  
	response[8] = 0x00                  
	response[9] = 0x00                  
	response[10] = 0x00                 
	response[11] = 0x00                 

	
	copy(response[12:], responseData)

	return response
}


func GenerateFakeDNSResponse(requestData []byte) []byte {
	
	
	
	if len(requestData) < 2 {
		
		return []byte{0x00, 0x00, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	}

	
	response := make([]byte, 12)
	copy(response[:2], requestData[:2]) 
	response[2] = 0x81                  
	response[3] = 0x83                  
	response[4] = 0x00                  
	response[5] = 0x01                  
	response[6] = 0x00                  
	response[7] = 0x00                  
	response[8] = 0x00                  
	response[9] = 0x00                  
	response[10] = 0x00                 
	response[11] = 0x00                 

	return response
}




func generateRandomHexString(length int) string {
	bytes := make([]byte, length/2)
	rand.Read(bytes)
	
	hexChars := []byte("0123456789abcdef")
	result := make([]byte, length)
	
	for i, b := range bytes {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0F]
	}
	
	return string(result)
}



func GenerateRandomHexString(length int) string {
	return generateRandomHexString(length)
}


func GenerateTUNConfigPacket(localIP, remoteIP string, mtu uint16) *Packet {
	
	dataSize := 2 + 1 + len(localIP) + 1 + len(remoteIP)
	
	
	data := make([]byte, dataSize)
	offset := 0
	
	
	binary.BigEndian.PutUint16(data[offset:offset+2], mtu)
	offset += 2
	
	
	data[offset] = byte(len(localIP))
	offset++
	copy(data[offset:], []byte(localIP))
	offset += len(localIP)
	
	
	data[offset] = byte(len(remoteIP))
	offset++
	copy(data[offset:], []byte(remoteIP))
	
	
	return &Packet{
		Header: &PacketHeader{
			PacketType: PacketTypeTUNConfig,
			PacketSize: uint32(len(data)),
		},
		Data: data,
	}
}


func ParseTUNConfigPacket(data []byte) (localIP, remoteIP string, mtu uint16, err error) {
	if len(data) < 4 {
		return "", "", 0, errors.New("недостаточно данных в пакете TUN-конфигурации")
	}
	
	
	mtu = binary.BigEndian.Uint16(data[0:2])
	
	
	localIPLen := int(data[2])
	if 3+localIPLen > len(data) {
		return "", "", 0, errors.New("недостаточно данных для локального IP")
	}
	
	
	localIP = string(data[3 : 3+localIPLen])
	
	
	if 3+localIPLen >= len(data) {
		return "", "", 0, errors.New("недостаточно данных для длины удаленного IP")
	}
	remoteIPLen := int(data[3+localIPLen])
	
	
	if 3+localIPLen+1+remoteIPLen > len(data) {
		return "", "", 0, errors.New("недостаточно данных для удаленного IP")
	}
	
	
	remoteIP = string(data[3+localIPLen+1 : 3+localIPLen+1+remoteIPLen])
	
	return localIP, remoteIP, mtu, nil
}


func GenerateTUNIPPacket(clientIP, serverIP string, routes []string) *Packet {
	
	dataSize := 1 + len(clientIP) + 1 + len(serverIP) + 1
	
	
	for _, route := range routes {
		dataSize += 1 + len(route)
	}
	
	
	data := make([]byte, dataSize)
	offset := 0
	
	
	data[offset] = byte(len(clientIP))
	offset++
	copy(data[offset:], []byte(clientIP))
	offset += len(clientIP)
	
	
	data[offset] = byte(len(serverIP))
	offset++
	copy(data[offset:], []byte(serverIP))
	offset += len(serverIP)
	
	
	data[offset] = byte(len(routes))
	offset++
	
	
	for _, route := range routes {
		data[offset] = byte(len(route))
		offset++
		copy(data[offset:], []byte(route))
		offset += len(route)
	}
	
	
	return &Packet{
		Header: &PacketHeader{
			PacketType: PacketTypeTUNIP,
			PacketSize: uint32(len(data)),
		},
		Data: data,
	}
}


func ParseTUNIPPacket(data []byte) (string, string, []string, error) {
	if len(data) < 3 {
		return "", "", nil, errors.New("недостаточно данных в пакете TUN-IP")
	}

	offset := 0

	
	clientIPLen := int(data[offset])
	offset++

	if offset+clientIPLen > len(data) {
		return "", "", nil, errors.New("недостаточно данных для IP клиента")
	}
	clientIP := string(data[offset : offset+clientIPLen])
	offset += clientIPLen

	
	if offset >= len(data) {
		return "", "", nil, errors.New("недостаточно данных для длины IP сервера")
	}

	serverIPLen := int(data[offset])
	offset++

	if offset+serverIPLen > len(data) {
		return "", "", nil, errors.New("недостаточно данных для IP сервера")
	}
	serverIP := string(data[offset : offset+serverIPLen])
	offset += serverIPLen

	
	if offset >= len(data) {
		return clientIP, serverIP, nil, nil 
	}

	routesCount := int(data[offset])
	offset++

	routes := make([]string, 0, routesCount)

	
	for i := 0; i < routesCount; i++ {
		if offset >= len(data) {
			break 
		}

		routeLen := int(data[offset])
		offset++

		if offset+routeLen > len(data) {
			break 
		}

		route := string(data[offset : offset+routeLen])
		routes = append(routes, route)
		offset += routeLen
	}

	return clientIP, serverIP, routes, nil
}


func GenerateTUNDataPacket(data []byte) *Packet {
	
	return &Packet{
		Header: &PacketHeader{
			PacketType: PacketTypeTUNData,
			PacketSize: uint32(len(data)),
		},
		Data: data,
	}
}


func SerializeHeader(header *PacketHeader) []byte {
	result := make([]byte, HeaderSize)
	
	
	result[0] = header.PacketType
	
	
	binary.BigEndian.PutUint32(result[1:5], header.PacketSize)
	
	return result
} 