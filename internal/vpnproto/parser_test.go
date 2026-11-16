// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package vpnproto

import (
	"bytes"
	"testing"

	Enums "masterdnsvpn-go/internal/enums"
)

// buildRawPacket assembles an inner v1 frame by hand, independently of BuildRaw:
// type, then the extensions the type carries, then the payload.
func buildRawPacket(
	t *testing.T,
	packetType uint8,
	streamID uint16,
	sequenceNum uint16,
	fragmentID uint8,
	totalFragments uint8,
	compressionType uint8,
	payload []byte,
) []byte {
	t.Helper()

	raw := make([]byte, 0, 16+len(payload))
	raw = append(raw, packetType)
	if hasStreamExtension(packetType) {
		raw = append(raw, byte(streamID>>8), byte(streamID))
	}
	if hasSequenceExtension(packetType) {
		raw = append(raw, byte(sequenceNum>>8), byte(sequenceNum))
	}
	if hasFragmentExtension(packetType) {
		raw = append(raw, fragmentID, totalFragments)
	}
	if hasCompressionExtension(packetType) {
		raw = append(raw, compressionType)
	}
	return append(raw, payload...)
}

func TestParseSessionInitPacket(t *testing.T) {
	payload := []byte("hello")
	raw := buildRawPacket(t, Enums.PACKET_SESSION_INIT, 0, 0, 0, 0, 0, payload)

	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if parsed.PacketType != Enums.PACKET_SESSION_INIT {
		t.Fatalf("unexpected base fields: %+v", parsed)
	}
	if parsed.HasStreamID || parsed.HasSequenceNum || parsed.HasFragmentInfo || parsed.HasCompressionType {
		t.Fatalf("unexpected optional fields for session init: %+v", parsed)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatalf("unexpected payload: got=%q want=%q", parsed.Payload, payload)
	}
}

func TestParseStreamDataPacket(t *testing.T) {
	payload := []byte("vpn-data")
	raw := buildRawPacket(t, Enums.PACKET_STREAM_DATA, 0x1122, 0x3344, 5, 9, 2, payload)

	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if !parsed.HasStreamID || parsed.StreamID != 0x1122 {
		t.Fatalf("unexpected stream id: %+v", parsed)
	}
	if !parsed.HasSequenceNum || parsed.SequenceNum != 0x3344 {
		t.Fatalf("unexpected sequence number: %+v", parsed)
	}
	if !parsed.HasFragmentInfo || parsed.FragmentID != 5 || parsed.TotalFragments != 9 {
		t.Fatalf("unexpected fragment info: %+v", parsed)
	}
	if !parsed.HasCompressionType || parsed.CompressionType != 2 {
		t.Fatalf("unexpected compression info: %+v", parsed)
	}
	if parsed.HeaderLength != 8 {
		t.Fatalf("unexpected header length: got=%d want=%d", parsed.HeaderLength, 8)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatalf("unexpected payload: got=%q want=%q", parsed.Payload, payload)
	}
}

func TestPacketBuilderLeavesOnlyInnerFieldsInPlaintext(t *testing.T) {
	payload := []byte("payload")
	built, err := BuildRaw(BuildOptions{
		SessionID:       3,
		PacketType:      Enums.PACKET_STREAM_DATA,
		StreamID:        100,
		SequenceNum:     200,
		FragmentID:      1,
		TotalFragments:  2,
		CompressionType: 1,
		Payload:         payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := buildRawPacket(t, Enums.PACKET_STREAM_DATA, 100, 200, 1, 2, 1, payload)
	if !bytes.Equal(built, want) {
		t.Fatalf("BuildRaw layout mismatch: got %x want %x", built, want)
	}
	if len(built) != 8+len(payload) {
		t.Fatalf("inner STREAM_DATA header must be 8 bytes (type, stream, seq, frag id/total, compression), got %d", len(built)-len(payload))
	}
	if HeaderRawSize(Enums.PACKET_PING) != 1 {
		t.Fatalf("PING inner header must be one byte, got %d", HeaderRawSize(Enums.PACKET_PING))
	}
}

func FuzzParseInflated(f *testing.F) {
	f.Add(append([]byte{Enums.PACKET_STREAM_DATA, 0, 1, 0, 2, 0, 1, 0}, "payload"...))
	f.Add([]byte{Enums.PACKET_PING})
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		packet, err := ParseInflated(data)
		if err == nil && packet.HeaderLength > len(data) {
			t.Fatalf("header length %d beyond input %d", packet.HeaderLength, len(data))
		}
	})
}
