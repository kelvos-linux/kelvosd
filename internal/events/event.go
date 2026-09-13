package events

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const wireSize = 44

type TrafficEvent struct {
	TimestampNS uint32
	IfIndex     uint32
	EthProto    uint16
	IPVersion   uint8
	IPTTL       uint8
	IPTotalLen  uint16
	IPSource    uint32
	IPDest      uint32
	Transport   uint8
	SourcePort  uint16
	DestPort    uint16
	TCPFlags    uint8
	TCPSeq      uint32
	TCPAck      uint32
	TCPWindow   uint16
	PayloadLen  uint16
}

func Decode(data []byte) (TrafficEvent, error) {
	if len(data) < wireSize {
		return TrafficEvent{}, fmt.Errorf("event is %d bytes, want at least %d", len(data), wireSize)
	}
	return TrafficEvent{
		TimestampNS: binary.LittleEndian.Uint32(data[0:4]),
		IfIndex:     binary.LittleEndian.Uint32(data[4:8]),
		EthProto:    binary.BigEndian.Uint16(data[8:10]),
		IPVersion:   data[10], IPTTL: data[11],
		IPTotalLen: binary.BigEndian.Uint16(data[12:14]),
		IPSource:   binary.LittleEndian.Uint32(data[16:20]),
		IPDest:     binary.LittleEndian.Uint32(data[20:24]),
		Transport:  data[24],
		SourcePort: binary.BigEndian.Uint16(data[26:28]),
		DestPort:   binary.BigEndian.Uint16(data[28:30]),
		TCPFlags:   data[30],
		TCPSeq:     binary.BigEndian.Uint32(data[32:36]),
		TCPAck:     binary.BigEndian.Uint32(data[36:40]),
		TCPWindow:  binary.BigEndian.Uint16(data[40:42]),
		PayloadLen: binary.BigEndian.Uint16(data[42:44]),
	}, nil
}

func (e TrafficEvent) Record(interfaceName string) map[string]any {
	protocol := "Other"
	if e.Transport == 6 {
		protocol = "TCP"
	} else if e.Transport == 17 {
		protocol = "UDP"
	}
	return map[string]any{
		"timestamp": time.Unix(0, int64(e.TimestampNS)).UTC().Format("2006-01-02T15:04:05.000000000Z"),
		"interface": interfaceName,
		"direction": "ingress",
		"ethernet": map[string]any{
			"destination_mac": "00:00:00:00:00:00",
			"source_mac":      "00:00:00:00:00:00",
			"ethertype":       fmt.Sprintf("0x%04x", e.EthProto),
			"vlan":            map[string]any{"enabled": false, "id": nil, "priority": nil},
		},
		"network": map[string]any{
			"protocol": map[bool]string{true: "IPv4", false: "Non-IP"}[e.IPVersion == 4],
			"version":  e.IPVersion, "header_length": 20, "total_length": e.IPTotalLen,
			"ttl": e.IPTTL, "protocol_number": e.Transport,
			"source_ip": ipv4(e.IPSource), "destination_ip": ipv4(e.IPDest),
		},
		"transport": map[string]any{
			"protocol": protocol, "source_port": e.SourcePort, "destination_port": e.DestPort,
			"sequence_number": e.TCPSeq, "acknowledgement_number": e.TCPAck,
			"flags": map[string]bool{
				"syn": e.TCPFlags&1 != 0, "ack": e.TCPFlags&2 != 0, "fin": e.TCPFlags&4 != 0,
				"rst": e.TCPFlags&8 != 0, "psh": e.TCPFlags&16 != 0, "urg": e.TCPFlags&32 != 0,
			},
			"window_size": e.TCPWindow,
		},
		"application": map[string]any{"protocol": "Unknown", "server_name": nil, "alpn": nil, "http": nil, "dns": nil},
		"payload":     map[string]any{"length": e.PayloadLen, "encoding": "none", "data": ""},
		"flow":        map[string]any{"flow_id": "unset", "stream_id": 0, "session_id": "unset"},
		"metadata":    map[string]any{"capture_method": "XDP", "kernel_timestamp": true},
	}
}

func ipv4(value uint32) string {
	return net.IPv4(byte(value), byte(value>>8), byte(value>>16), byte(value>>24)).String()
}
