package protocol

import (
	"bytes"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"math/rand"
	"strings"
	"time"
)

const (
	DNSTypeA     uint16 = 1
	DNSTypeTXT   uint16 = 16
	DNSTypeAAAA  uint16 = 28
	DNSTypeCNAME uint16 = 5
)


func ParseDNSQuery(data []byte) ([]byte, string, uint16, error) {
	if len(data) < 12 {
		return nil, "", 0, errors.New("DNS header too short")
	}

	
	header := data[:12]

	
	offset := 12
	var domain strings.Builder
	
	for {
		if offset >= len(data) {
			return nil, "", 0, errors.New("malformed DNS query")
		}
		
		length := int(data[offset])
		offset++
		
		if length == 0 {
			break
		}
		
		if offset+length > len(data) {
			return nil, "", 0, errors.New("malformed DNS query")
		}
		
		if domain.Len() > 0 {
			domain.WriteByte('.')
		}
		
		domain.Write(data[offset : offset+length])
		offset += length
	}
	
	
	if offset+2 > len(data) {
		return nil, "", 0, errors.New("malformed DNS query")
	}
	
	queryType := uint16(data[offset])<<8 | uint16(data[offset+1])
	
	return header, domain.String(), queryType, nil
}


func EncodeDNSPayload(data []byte) string {
	
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	
	
	var result strings.Builder
	for i := 0; i < len(encoded); i += 63 {
		end := i + 63
		if end > len(encoded) {
			end = len(encoded)
		}
		
		if i > 0 {
			result.WriteByte('.')
		}
		
		result.WriteString(encoded[i:end])
	}
	
	return result.String()
}


func DecodeDNSPayload(encoded string) ([]byte, error) {
	
	encoded = strings.ReplaceAll(encoded, ".", "")
	
	
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	
	return decoded, nil
}


func GenerateDNSResponse(header []byte, domainName string, responseData []byte, queryType uint16) []byte {
	
	respHeader := make([]byte, len(header))
	copy(respHeader, header)
	
	
	respHeader[2] |= 0x80
	
	
	respHeader[3] |= 0x80
	
	
	var buffer bytes.Buffer
	
	
	buffer.Write(respHeader)
	
	
	parts := strings.Split(domainName, ".")
	for _, part := range parts {
		buffer.WriteByte(byte(len(part)))
		buffer.WriteString(part)
	}
	buffer.WriteByte(0)
	
	
	buffer.WriteByte(byte(queryType >> 8))
	buffer.WriteByte(byte(queryType & 0xFF))
	buffer.WriteByte(0x00) 
	buffer.WriteByte(0x01)
	
	
	
	buffer.WriteByte(0xC0)
	buffer.WriteByte(0x0C) 
	
	
	buffer.WriteByte(byte(queryType >> 8))
	buffer.WriteByte(byte(queryType & 0xFF))
	buffer.WriteByte(0x00) 
	buffer.WriteByte(0x01)
	
	
	buffer.WriteByte(0x00)
	buffer.WriteByte(0x00)
	buffer.WriteByte(0x00)
	buffer.WriteByte(0x3C)
	
	
	switch queryType {
	case DNSTypeA:
		
		buffer.WriteByte(0x00)
		buffer.WriteByte(0x04)
		
		
		if len(responseData) < 4 {
			
			buffer.WriteByte(byte(10 + rand.Intn(10)))
			buffer.WriteByte(byte(rand.Intn(255)))
			buffer.WriteByte(byte(rand.Intn(255)))
			buffer.WriteByte(byte(rand.Intn(255)))
		} else {
			
			buffer.Write(responseData[:4])
		}
	case DNSTypeTXT:
		
		encoded := base64.StdEncoding.EncodeToString(responseData)
		
		
		if len(encoded) > 255 {
			encoded = encoded[:255]
		}
		
		
		buffer.WriteByte(0x00)
		buffer.WriteByte(byte(len(encoded) + 1))
		
		
		buffer.WriteByte(byte(len(encoded)))
		
		
		buffer.WriteString(encoded)
	}
	
	return buffer.Bytes()
}


func GenerateFakeDNSResponse(dnsRequest []byte) []byte {
	if len(dnsRequest) < 12 {
		
		return dnsRequest
	}
	
	
	header := make([]byte, 12)
	copy(header, dnsRequest[:12])
	
	
	header[2] |= 0x80
	
	
	header[3] |= 0x80
	
	
	var buffer bytes.Buffer
	buffer.Write(header)
	
	
	domainEnd := 12
	for domainEnd < len(dnsRequest) {
		if dnsRequest[domainEnd] == 0 {
			domainEnd++
			break
		}
		
		
		if dnsRequest[domainEnd] == 0 {
			domainEnd++
		} else {
			domainEnd += int(dnsRequest[domainEnd]) + 1
		}
	}
	
	
	if domainEnd > 12 && domainEnd < len(dnsRequest) {
		buffer.Write(dnsRequest[12:domainEnd])
	} else {
		buffer.WriteByte(0) 
	}
	
	
	if domainEnd+4 <= len(dnsRequest) {
		buffer.Write(dnsRequest[domainEnd:domainEnd+4])
		
		
		queryType := uint16(dnsRequest[domainEnd])<<8 | uint16(dnsRequest[domainEnd+1])
		
		
		buffer.WriteByte(0xC0)
		buffer.WriteByte(0x0C) 
		
		
		buffer.Write(dnsRequest[domainEnd:domainEnd+4])
		
		
		buffer.WriteByte(0x00)
		buffer.WriteByte(0x00)
		buffer.WriteByte(0x01)
		buffer.WriteByte(0x2C)
		
		
		switch queryType {
		case DNSTypeA:
			
			buffer.WriteByte(0x00)
			buffer.WriteByte(0x04)
			
			
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			
			
			firstOctet := []byte{8, 64, 74, 198, 102, 199}[r.Intn(6)]
			buffer.WriteByte(firstOctet)
			buffer.WriteByte(byte(r.Intn(255)))
			buffer.WriteByte(byte(r.Intn(255)))
			buffer.WriteByte(byte(r.Intn(255)))
		case DNSTypeTXT:
			
			txt := generateRandomText(r.Intn(30) + 10)
			
			
			buffer.WriteByte(0x00)
			buffer.WriteByte(byte(len(txt) + 1))
			
			
			buffer.WriteByte(byte(len(txt)))
			
			
			buffer.WriteString(txt)
		case DNSTypeAAAA:
			
			buffer.WriteByte(0x00)
			buffer.WriteByte(0x10)
			
			
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			ipv6 := make([]byte, 16)
			r.Read(ipv6)
			
			
			ipv6[0] = 0x2a
			ipv6[1] = 0x00
			
			buffer.Write(ipv6)
		case DNSTypeCNAME:
			
			cname := generateRandomDomain()
			
			
			buffer.WriteByte(0x00)
			buffer.WriteByte(byte(len(cname) + 2))
			
			
			parts := strings.Split(cname, ".")
			for _, part := range parts {
				buffer.WriteByte(byte(len(part)))
				buffer.WriteString(part)
			}
			buffer.WriteByte(0)
		default:
			
			buffer.WriteByte(0x00)
			buffer.WriteByte(0x00)
		}
	}
	
	return buffer.Bytes()
}


func generateRandomText(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func generateRandomDomain() string {
	domains := []string{
		"example.com",
		"example.org",
		"example.net",
		"test.com",
		"test.org",
		"server.net",
		"cdn.com",
		"static.org",
		"api.com",
		"docs.org",
	}
	
	subdomains := []string{
		"www",
		"mail",
		"ftp",
		"cdn",
		"api",
		"static",
		"images",
		"docs",
		"cloud",
		"login",
	}
	
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	
	
	if r.Intn(2) == 0 {
		return domains[r.Intn(len(domains))]
	} else {
		return subdomains[r.Intn(len(subdomains))] + "." + domains[r.Intn(len(domains))]
	}
} 