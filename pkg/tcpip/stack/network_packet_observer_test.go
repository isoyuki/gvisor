package stack

import (
	"testing"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type testNetworkPacketObserver struct {
	observing bool
	checks    int
	events    []NetworkPacketEvent
}

func (o *testNetworkPacketObserver) IsObservingNetworkPackets(NetworkPacketDirection) bool {
	o.checks++
	return o.observing
}

func (o *testNetworkPacketObserver) ObserveNetworkPacket(evt NetworkPacketEvent) {
	o.events = append(o.events, evt)
}

func TestObserveNetworkPacketIPv4UDP(t *testing.T) {
	const (
		srcPort = 1234
		dstPort = 5678
	)
	srcAddr := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	dstAddr := tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: header.IPv4MinimumSize + header.UDPMinimumSize,
	})
	defer pkt.DecRef()
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	udp.SetSourcePort(srcPort)
	udp.SetDestinationPort(dstPort)
	udp.SetLength(uint16(header.UDPMinimumSize))
	pkt.TransportProtocolNumber = header.UDPProtocolNumber
	ip := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + header.UDPMinimumSize),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber

	observer := &testNetworkPacketObserver{observing: true}
	s := &Stack{networkPacketObserver: observer}
	s.observeNetworkPacket(NetworkPacketEgress, 2, header.IPv4ProtocolNumber, pkt)
	if len(observer.events) != 1 {
		t.Fatalf("got %d events, want 1", len(observer.events))
	}
	evt := observer.events[0]
	if evt.Direction != NetworkPacketEgress || evt.NICID != 2 || evt.NetworkProtocol != header.IPv4ProtocolNumber || evt.TransportProtocol != header.UDPProtocolNumber {
		t.Fatalf("unexpected event metadata: %+v", evt)
	}
	if evt.TotalLength != header.IPv4MinimumSize+header.UDPMinimumSize {
		t.Fatalf("TotalLength = %d, want %d", evt.TotalLength, header.IPv4MinimumSize+header.UDPMinimumSize)
	}
	if evt.SourcePort != srcPort || evt.DestinationPort != dstPort {
		t.Fatalf("ports = %d/%d, want %d/%d", evt.SourcePort, evt.DestinationPort, srcPort, dstPort)
	}
	var gotSrc [4]byte
	copy(gotSrc[:], evt.SourceAddress[:4])
	if got := tcpip.AddrFrom4(gotSrc); got != srcAddr {
		t.Fatalf("SourceAddress = %s, want %s", got, srcAddr)
	}
	var gotDst [4]byte
	copy(gotDst[:], evt.DestinationAddress[:4])
	if got := tcpip.AddrFrom4(gotDst); got != dstAddr {
		t.Fatalf("DestinationAddress = %s, want %s", got, dstAddr)
	}
}

func TestObserveNetworkPacketDisabledSkipsEvent(t *testing.T) {
	pkt := newIPv4UDPPacketWithHeaders(header.IPv4MinimumSize, 0)
	defer pkt.DecRef()
	observer := &testNetworkPacketObserver{}
	s := &Stack{networkPacketObserver: observer}
	s.observeNetworkPacket(NetworkPacketIngress, 1, header.IPv4ProtocolNumber, pkt)
	if observer.checks != 1 {
		t.Fatalf("IsObservingNetworkPackets called %d times, want 1", observer.checks)
	}
	if len(observer.events) != 0 {
		t.Fatalf("got %d events, want 0", len(observer.events))
	}
}

func TestObserveNetworkPacketIPv4FragmentSkipsPorts(t *testing.T) {
	pkt := newIPv4UDPPacketWithHeaders(header.IPv4MinimumSize, 8)
	defer pkt.DecRef()
	evt := observeOnePacket(t, pkt, header.IPv4ProtocolNumber)
	if evt.TransportProtocol != header.UDPProtocolNumber {
		t.Fatalf("TransportProtocol = %d, want UDP", evt.TransportProtocol)
	}
	if evt.SourcePort != 0 || evt.DestinationPort != 0 {
		t.Fatalf("ports = %d/%d, want 0/0", evt.SourcePort, evt.DestinationPort)
	}
}

func TestObserveNetworkPacketIPv4OptionsSplitHeader(t *testing.T) {
	const ipv4HeaderLength = header.IPv4MinimumSize + 4
	pkt := newIPv4UDPPacketWithShortConsumedNetworkHeader(ipv4HeaderLength, header.IPv4MinimumSize)
	defer pkt.DecRef()
	evt := observeOnePacket(t, pkt, header.IPv4ProtocolNumber)
	if evt.SourcePort != 1234 || evt.DestinationPort != 5678 {
		t.Fatalf("ports = %d/%d, want 1234/5678", evt.SourcePort, evt.DestinationPort)
	}
}

func TestObserveNetworkPacketIPv4FullPacketInData(t *testing.T) {
	pkt := newIPv4UDPPacketInData(header.IPv4MinimumSize, 0)
	defer pkt.DecRef()
	evt := observeOnePacket(t, pkt, header.IPv4ProtocolNumber)
	if evt.SourcePort != 1234 || evt.DestinationPort != 5678 {
		t.Fatalf("ports = %d/%d, want 1234/5678", evt.SourcePort, evt.DestinationPort)
	}
}

func TestObserveNetworkPacketTotalLengthIsPacketSize(t *testing.T) {
	b := newIPv4UDPBytes(header.IPv4MinimumSize, 0)
	header.IPv4(b[:header.IPv4MinimumSize]).SetTotalLength(4)
	pkt := newPacketInData(b)
	defer pkt.DecRef()
	evt := observeOnePacket(t, pkt, header.IPv4ProtocolNumber)
	if evt.TotalLength != uint32(len(b)) {
		t.Fatalf("TotalLength = %d, want observed packet size %d", evt.TotalLength, len(b))
	}
}

func TestObserveNetworkPacketIPv4NetworkHeaderOnly(t *testing.T) {
	pkt := newIPv4UDPPacketWithConsumedNetworkHeader(header.IPv4MinimumSize)
	defer pkt.DecRef()
	evt := observeOnePacket(t, pkt, header.IPv4ProtocolNumber)
	if evt.SourcePort != 1234 || evt.DestinationPort != 5678 {
		t.Fatalf("ports = %d/%d, want 1234/5678", evt.SourcePort, evt.DestinationPort)
	}
}

func TestObserveNetworkPacketIPv4TCP(t *testing.T) {
	const (
		srcPort = 2233
		dstPort = 4455
	)
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: header.IPv4MinimumSize + header.TCPMinimumSize,
	})
	defer pkt.DecRef()
	tcp := header.TCP(pkt.TransportHeader().Push(header.TCPMinimumSize))
	tcp.SetSourcePort(srcPort)
	tcp.SetDestinationPort(dstPort)
	pkt.TransportProtocolNumber = header.TCPProtocolNumber
	ip := header.IPv4(pkt.NetworkHeader().Push(header.IPv4MinimumSize))
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(header.IPv4MinimumSize + header.TCPMinimumSize),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
		DstAddr:     tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
	})
	evt := observeOnePacket(t, pkt, header.IPv4ProtocolNumber)
	if evt.SourcePort != srcPort || evt.DestinationPort != dstPort {
		t.Fatalf("ports = %d/%d, want %d/%d", evt.SourcePort, evt.DestinationPort, srcPort, dstPort)
	}
}

func TestObserveNetworkPacketIPv6UDP(t *testing.T) {
	pkt := newIPv6UDPPacket(false)
	defer pkt.DecRef()
	evt := observeOnePacket(t, pkt, header.IPv6ProtocolNumber)
	if evt.TransportProtocol != header.UDPProtocolNumber {
		t.Fatalf("TransportProtocol = %d, want UDP", evt.TransportProtocol)
	}
	if evt.SourcePort != 1234 || evt.DestinationPort != 5678 {
		t.Fatalf("ports = %d/%d, want 1234/5678", evt.SourcePort, evt.DestinationPort)
	}
}

func TestObserveNetworkPacketIPv6ExtensionHeader(t *testing.T) {
	pkt := newIPv6UDPPacket(true)
	defer pkt.DecRef()
	evt := observeOnePacket(t, pkt, header.IPv6ProtocolNumber)
	if evt.TransportProtocol != header.UDPProtocolNumber {
		t.Fatalf("TransportProtocol = %d, want UDP", evt.TransportProtocol)
	}
	if evt.SourcePort != 1234 || evt.DestinationPort != 5678 {
		t.Fatalf("ports = %d/%d, want 1234/5678", evt.SourcePort, evt.DestinationPort)
	}
}

func TestObserveNetworkPacketIPv6NonInitialFragmentSkipsPorts(t *testing.T) {
	pkt := newIPv6FragmentedUDPPacket()
	defer pkt.DecRef()
	evt := observeOnePacket(t, pkt, header.IPv6ProtocolNumber)
	if evt.TransportProtocol != header.UDPProtocolNumber {
		t.Fatalf("TransportProtocol = %d, want UDP", evt.TransportProtocol)
	}
	if evt.SourcePort != 0 || evt.DestinationPort != 0 {
		t.Fatalf("ports = %d/%d, want 0/0", evt.SourcePort, evt.DestinationPort)
	}
}

func TestObserveNetworkPacketShortPackets(t *testing.T) {
	for _, protocol := range []tcpip.NetworkProtocolNumber{header.IPv4ProtocolNumber, header.IPv6ProtocolNumber} {
		var buf buffer.Buffer
		buf.Append(buffer.NewViewSize(4))
		pkt := NewPacketBuffer(PacketBufferOptions{Payload: buf})
		evt := observeOnePacket(t, pkt, protocol)
		pkt.DecRef()
		if evt.TransportProtocol != 0 || evt.SourcePort != 0 || evt.DestinationPort != 0 {
			t.Fatalf("protocol %d produced transport metadata from a short packet: %+v", protocol, evt)
		}
	}
}

func BenchmarkObserveNetworkPacketDisabled(b *testing.B) {
	pkt := newIPv4UDPPacketWithHeaders(header.IPv4MinimumSize, 0)
	defer pkt.DecRef()
	s := &Stack{networkPacketObserver: &testNetworkPacketObserver{}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.observeNetworkPacket(NetworkPacketIngress, 1, header.IPv4ProtocolNumber, pkt)
	}
}

func observeOnePacket(t *testing.T, pkt *PacketBuffer, protocol tcpip.NetworkProtocolNumber) NetworkPacketEvent {
	t.Helper()
	observer := &testNetworkPacketObserver{observing: true}
	s := &Stack{networkPacketObserver: observer}
	s.observeNetworkPacket(NetworkPacketIngress, 2, protocol, pkt)
	if len(observer.events) != 1 {
		t.Fatalf("got %d events, want 1", len(observer.events))
	}
	return observer.events[0]
}

func newIPv4UDPBytes(ipHeaderLen int, fragmentOffset uint16) []byte {
	b := make([]byte, ipHeaderLen+header.UDPMinimumSize)
	ip := header.IPv4(b[:ipHeaderLen])
	ip.Encode(&header.IPv4Fields{
		TotalLength:    uint16(len(b)),
		TTL:            64,
		Protocol:       uint8(header.UDPProtocolNumber),
		FragmentOffset: fragmentOffset,
		SrcAddr:        tcpip.AddrFrom4([4]byte{10, 0, 0, 1}),
		DstAddr:        tcpip.AddrFrom4([4]byte{10, 0, 0, 2}),
	})
	ip.SetHeaderLength(uint8(ipHeaderLen))
	udp := header.UDP(b[ipHeaderLen:])
	udp.SetSourcePort(1234)
	udp.SetDestinationPort(5678)
	udp.SetLength(uint16(header.UDPMinimumSize))
	return b
}

func newIPv4UDPPacketWithHeaders(ipHeaderLen int, fragmentOffset uint16) *PacketBuffer {
	b := newIPv4UDPBytes(ipHeaderLen, fragmentOffset)
	pkt := NewPacketBuffer(PacketBufferOptions{ReserveHeaderBytes: len(b)})
	copy(pkt.TransportHeader().Push(header.UDPMinimumSize), b[ipHeaderLen:])
	copy(pkt.NetworkHeader().Push(ipHeaderLen), b[:ipHeaderLen])
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber
	pkt.TransportProtocolNumber = header.UDPProtocolNumber
	return pkt
}

func newIPv4UDPPacketInData(ipHeaderLen int, fragmentOffset uint16) *PacketBuffer {
	return newPacketInData(newIPv4UDPBytes(ipHeaderLen, fragmentOffset))
}

func newIPv4UDPPacketWithConsumedNetworkHeader(ipHeaderLen int) *PacketBuffer {
	pkt := newIPv4UDPPacketInData(ipHeaderLen, 0)
	if _, ok := pkt.NetworkHeader().Consume(ipHeaderLen); !ok {
		panic("failed to consume IPv4 header")
	}
	return pkt
}

func newIPv4UDPPacketWithShortConsumedNetworkHeader(ipHeaderLen, consumedLen int) *PacketBuffer {
	pkt := newIPv4UDPPacketInData(ipHeaderLen, 0)
	if _, ok := pkt.NetworkHeader().Consume(consumedLen); !ok {
		panic("failed to consume IPv4 header")
	}
	return pkt
}

func newIPv6UDPPacket(withExtension bool) *PacketBuffer {
	payloadLen := header.UDPMinimumSize
	if withExtension {
		payloadLen += 8
	}
	b := make([]byte, header.IPv6MinimumSize+payloadLen)
	transport := tcpip.TransportProtocolNumber(header.UDPProtocolNumber)
	if withExtension {
		transport = tcpip.TransportProtocolNumber(header.IPv6HopByHopOptionsExtHdrIdentifier)
	}
	ip := header.IPv6(b[:header.IPv6MinimumSize])
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLen),
		TransportProtocol: transport,
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
		DstAddr:           tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
	})
	udpOff := header.IPv6MinimumSize
	if withExtension {
		ext := b[header.IPv6MinimumSize : header.IPv6MinimumSize+8]
		ext[0] = uint8(header.UDPProtocolNumber)
		ext[1] = 0
		udpOff += 8
	}
	udp := header.UDP(b[udpOff:])
	udp.SetSourcePort(1234)
	udp.SetDestinationPort(5678)
	udp.SetLength(uint16(header.UDPMinimumSize))
	var buf buffer.Buffer
	buf.Append(buffer.NewViewWithData(b))
	pkt := NewPacketBuffer(PacketBufferOptions{Payload: buf})
	if _, ok := pkt.NetworkHeader().Consume(header.IPv6MinimumSize); !ok {
		panic("failed to consume IPv6 header")
	}
	return pkt
}

func newIPv6FragmentedUDPPacket() *PacketBuffer {
	payloadLen := header.IPv6FragmentHeaderSize + header.UDPMinimumSize
	b := make([]byte, header.IPv6MinimumSize+payloadLen)
	ip := header.IPv6(b[:header.IPv6MinimumSize])
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(payloadLen),
		TransportProtocol: tcpip.TransportProtocolNumber(header.IPv6FragmentExtHdrIdentifier),
		HopLimit:          64,
		SrcAddr:           tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}),
		DstAddr:           tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}),
	})
	frag := b[header.IPv6MinimumSize : header.IPv6MinimumSize+header.IPv6FragmentHeaderSize]
	frag[0] = uint8(header.UDPProtocolNumber)
	frag[3] = 8
	udp := header.UDP(b[header.IPv6MinimumSize+header.IPv6FragmentHeaderSize:])
	udp.SetSourcePort(1234)
	udp.SetDestinationPort(5678)
	udp.SetLength(uint16(header.UDPMinimumSize))
	pkt := newPacketInData(b)
	if _, ok := pkt.NetworkHeader().Consume(header.IPv6MinimumSize); !ok {
		panic("failed to consume IPv6 header")
	}
	return pkt
}

func newPacketInData(data []byte) *PacketBuffer {
	var buf buffer.Buffer
	buf.Append(buffer.NewViewWithData(data))
	return NewPacketBuffer(PacketBufferOptions{Payload: buf})
}
