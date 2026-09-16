package events

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const wireSize = 81

type TrafficEvent struct {
	TimestampNS uint64
	IfIndex     uint32
	EthProto    uint16
	IPVersion   uint8
	IPTTL       uint8
	IPTotalLen  uint16
	SourceMAC   [6]byte
	DestMAC     [6]byte
	Transport   uint8
	IPHeaderLen uint8
	SourcePort  uint16
	DestPort    uint16
	TCPFlags    uint8
	TCPSeq      uint32
	TCPAck      uint32
	TCPWindow   uint16
	PayloadLen  uint16
	IPSource    [16]byte
	IPDest      [16]byte
}

func Decode(data []byte) (TrafficEvent, error) {
	if len(data) < wireSize {
		return TrafficEvent{}, fmt.Errorf("event is %d bytes, want at least %d", len(data), wireSize)
	}
	return TrafficEvent{
		TimestampNS: binary.LittleEndian.Uint64(data[0:8]),
		IfIndex:     binary.LittleEndian.Uint32(data[8:12]),
		EthProto:    binary.BigEndian.Uint16(data[12:14]),
		IPVersion:   data[14], IPTTL: data[15],
		IPTotalLen: binary.LittleEndian.Uint16(data[16:18]),
		SourceMAC:  [6]byte{data[18], data[19], data[20], data[21], data[22], data[23]},
		DestMAC:    [6]byte{data[24], data[25], data[26], data[27], data[28], data[29]},
		Transport:  data[30], IPHeaderLen: data[31],
		SourcePort: binary.LittleEndian.Uint16(data[32:34]),
		DestPort:   binary.LittleEndian.Uint16(data[34:36]),
		TCPFlags:   data[36],
		TCPSeq:     binary.LittleEndian.Uint32(data[37:41]),
		TCPAck:     binary.LittleEndian.Uint32(data[41:45]),
		TCPWindow:  binary.LittleEndian.Uint16(data[45:47]),
		PayloadLen: binary.LittleEndian.Uint16(data[47:49]),
		IPSource:   [16]byte{data[49], data[50], data[51], data[52], data[53], data[54], data[55], data[56], data[57], data[58], data[59], data[60], data[61], data[62], data[63], data[64]},
		IPDest:     [16]byte{data[65], data[66], data[67], data[68], data[69], data[70], data[71], data[72], data[73], data[74], data[75], data[76], data[77], data[78], data[79], data[80]},
	}, nil
}

func (e TrafficEvent) Record(interfaceName, serviceName string) map[string]any {
	protocol := e.Protocol()
	if serviceName == "" {
		serviceName = "Unknown"
	}
	return map[string]any{
		"timestamp": time.Unix(0, int64(e.TimestampNS)).UTC().Format("2006-01-02T15:04:05.000000000Z"),
		"interface": interfaceName,
		"direction": "ingress",
		"ethernet": map[string]any{
			"destination_mac": net.HardwareAddr(e.DestMAC[:]).String(),
			"source_mac":      net.HardwareAddr(e.SourceMAC[:]).String(),
			"ethertype":       fmt.Sprintf("0x%04x", e.EthProto),
			"vlan":            map[string]any{"enabled": false, "id": nil, "priority": nil},
		},
		"network": map[string]any{
			"protocol": map[uint8]string{4: "IPv4", 6: "IPv6"}[e.IPVersion],
			"version":  e.IPVersion, "header_length": e.IPHeaderLen, "total_length": e.IPTotalLen,
			"ttl": e.IPTTL, "protocol_number": e.Transport,
			"source_ip": ipString(e.IPVersion, e.IPSource), "destination_ip": ipString(e.IPVersion, e.IPDest),
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
		"services": map[string]any{"protocol": serviceName},
		"payload":  map[string]any{"length": e.PayloadLen, "encoding": "none", "data": ""},
		"flow":     map[string]any{"flow_id": "unset", "stream_id": 0, "session_id": "unset"},
		"metadata": map[string]any{"capture_method": "XDP", "kernel_timestamp": true},
	}
}

func (e TrafficEvent) Protocol() string {
	if e.Transport == 6 {
		return "TCP"
	}
	if e.Transport == 17 {
		return "UDP"
	}
	return "Other"
}

func ipString(version uint8, value [16]byte) string {
	if version == 4 {
		return net.IPv4(value[0], value[1], value[2], value[3]).String()
	}
	if version == 6 {
		return net.IP(value[:]).String()
	}
	return "0.0.0.0"
}
