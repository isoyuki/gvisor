package stack

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func (s *Stack) observeNetworkPacket(direction NetworkPacketDirection, nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	if s == nil {
		return
	}
	observer := s.networkPacketObserver
	if observer == nil || pkt == nil {
		return
	}
	if !observer.IsObservingNetworkPackets(direction) {
		return
	}
	evt := NetworkPacketEvent{
		Direction:       direction,
		NICID:           nicID,
		NetworkProtocol: protocol,
		TotalLength:     uint32(pkt.Size()),
	}
	populateNetworkPacketEvent(&evt, pkt)
	observer.ObserveNetworkPacket(evt)
}

func populateNetworkPacketEvent(evt *NetworkPacketEvent, pkt *PacketBuffer) {
	switch evt.NetworkProtocol {
	case header.IPv4ProtocolNumber:
		populateIPv4PacketEvent(evt, pkt)
	case header.IPv6ProtocolNumber:
		populateIPv6PacketEvent(evt, pkt)
	}
}

func populateIPv4PacketEvent(evt *NetworkPacketEvent, pkt *PacketBuffer) {
	netHdr := packetNetworkBytes(pkt, header.IPv4MinimumSize)
	if len(netHdr) < header.IPv4MinimumSize {
		return
	}
	ip := header.IPv4(netHdr)
	hdrLen := int(ip.HeaderLength())
	if hdrLen < header.IPv4MinimumSize {
		return
	}
	netHdr = packetNetworkBytes(pkt, hdrLen)
	if len(netHdr) < hdrLen {
		return
	}
	ip = header.IPv4(netHdr)
	src := ip.SourceAddress()
	dst := ip.DestinationAddress()
	copy(evt.SourceAddress[:], src.AsSlice())
	copy(evt.DestinationAddress[:], dst.AsSlice())
	evt.TransportProtocol = ip.TransportProtocol()
	if ip.FragmentOffset() != 0 {
		return
	}
	payload := packetPayloadBytes(pkt, netHdr, hdrLen, transportHeaderMinSize(evt.TransportProtocol), true)
	populateTransportPorts(evt, payload)
}

func populateIPv6PacketEvent(evt *NetworkPacketEvent, pkt *PacketBuffer) {
	netHdr := packetNetworkBytes(pkt, header.IPv6MinimumSize)
	if len(netHdr) < header.IPv6MinimumSize {
		return
	}
	ip := header.IPv6(netHdr)
	src := ip.SourceAddress()
	dst := ip.DestinationAddress()
	copy(evt.SourceAddress[:], src.AsSlice())
	copy(evt.DestinationAddress[:], dst.AsSlice())
	payloadOff, proto, ok := ipv6TransportOffset(pkt, netHdr, uint8(ip.TransportProtocol()))
	evt.TransportProtocol = proto
	if !ok {
		return
	}
	payload := packetPayloadBytes(pkt, netHdr, payloadOff, transportHeaderMinSize(evt.TransportProtocol), true)
	populateTransportPorts(evt, payload)
}

func packetNetworkBytes(pkt *PacketBuffer, want int) []byte {
	if hdr := pkt.NetworkHeader().Slice(); len(hdr) != 0 {
		if len(hdr) >= want {
			return hdr
		}
		full := PayloadSince(pkt.NetworkHeader())
		if full != nil && full.Size() >= want {
			return full.AsSlice()
		}
		return hdr
	}
	if hdr, ok := pkt.Data().PullUp(want); ok {
		return hdr
	}
	return nil
}

func packetPayloadBytes(pkt *PacketBuffer, netHdr []byte, payloadOff int, want int, preferTransportHeader bool) []byte {
	if want == 0 {
		return nil
	}
	if hdr := pkt.TransportHeader().Slice(); preferTransportHeader && len(hdr) != 0 {
		return hdr
	}
	if payloadOff < len(netHdr) {
		payload := netHdr[payloadOff:]
		if len(payload) >= want {
			return payload
		}
	}
	if len(pkt.NetworkHeader().Slice()) != 0 {
		if hdr, ok := pkt.Data().PullUp(payloadOff - len(pkt.NetworkHeader().Slice()) + want); ok {
			return hdr[len(hdr)-want:]
		}
	} else if hdr, ok := pkt.Data().PullUp(payloadOff + want); ok {
		return hdr[payloadOff:]
	}
	return nil
}

func ipv6TransportOffset(pkt *PacketBuffer, netHdr []byte, nextHeader uint8) (int, tcpip.TransportProtocolNumber, bool) {
	off := header.IPv6MinimumSize
	proto := tcpip.TransportProtocolNumber(nextHeader)
	for i := 0; i < 8; i++ {
		switch header.IPv6ExtensionHeaderIdentifier(nextHeader) {
		case header.IPv6HopByHopOptionsExtHdrIdentifier, header.IPv6RoutingExtHdrIdentifier, header.IPv6DestinationOptionsExtHdrIdentifier:
			ext := packetPayloadBytes(pkt, netHdr, off, 2, false)
			if len(ext) < 2 {
				return off, proto, false
			}
			extLen := int(ext[1]+1) * 8
			ext = packetPayloadBytes(pkt, netHdr, off, extLen, false)
			if len(ext) < extLen {
				return off, proto, false
			}
			nextHeader = ext[0]
			proto = tcpip.TransportProtocolNumber(nextHeader)
			off += extLen
		case header.IPv6AuthenticationExtHdrIdentifier:
			ext := packetPayloadBytes(pkt, netHdr, off, 2, false)
			if len(ext) < 2 {
				return off, proto, false
			}
			extLen := int(ext[1]+2) * 4
			ext = packetPayloadBytes(pkt, netHdr, off, extLen, false)
			if len(ext) < extLen {
				return off, proto, false
			}
			nextHeader = ext[0]
			proto = tcpip.TransportProtocolNumber(nextHeader)
			off += extLen
		case header.IPv6FragmentExtHdrIdentifier:
			ext := packetPayloadBytes(pkt, netHdr, off, header.IPv6FragmentHeaderSize, false)
			if len(ext) < header.IPv6FragmentHeaderSize {
				return off, proto, false
			}
			frag := header.IPv6Fragment(ext)
			nextHeader = frag.NextHeader()
			proto = tcpip.TransportProtocolNumber(nextHeader)
			if frag.FragmentOffset() != 0 {
				return off + header.IPv6FragmentHeaderSize, proto, false
			}
			off += header.IPv6FragmentHeaderSize
		case header.IPv6NoNextHeaderIdentifier:
			return off, proto, false
		default:
			return off, proto, true
		}
	}
	return off, proto, false
}

func populateTransportPorts(evt *NetworkPacketEvent, payload []byte) {
	switch evt.TransportProtocol {
	case header.TCPProtocolNumber:
		if len(payload) >= header.TCPMinimumSize {
			tcp := header.TCP(payload)
			evt.SourcePort = tcp.SourcePort()
			evt.DestinationPort = tcp.DestinationPort()
		}
	case header.UDPProtocolNumber:
		if len(payload) >= header.UDPMinimumSize {
			udp := header.UDP(payload)
			evt.SourcePort = udp.SourcePort()
			evt.DestinationPort = udp.DestinationPort()
		}
	}
}

func transportHeaderMinSize(proto tcpip.TransportProtocolNumber) int {
	switch proto {
	case header.TCPProtocolNumber:
		return header.TCPMinimumSize
	case header.UDPProtocolNumber:
		return header.UDPMinimumSize
	default:
		return 0
	}
}
