package vpnproto

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	SessionAcceptPolicyPayloadSize = 13
	SessionAcceptV1PolicySize      = 1 + 4 + SessionAcceptPolicyPayloadSize

	SessionPolicyScaledMin = 0.05
	SessionPolicyScaledMax = 1.0
)

// SessionAcceptPayload holds the values carried in the encrypted v1 ACCEPT. The
// plaintext of the ACCEPT is the session ID followed by the policy block:
//
//	byte 0      : session ID (outside the policy block)
//	byte 1      : upload/download compression pair
//	bytes 2-5   : verify code
//	byte 6      : lower nibble = max packet duplication, upper nibble = max setup duplication
//	byte 7      : max upload MTU
//	bytes 8-9   : max download MTU
//	byte 10     : max RX/TX workers
//	byte 11     : min ping aggressive interval (scaled 0..255 => 0.05..1.00s)
//	byte 12     : max packets per batch
//	bytes 13-14 : max ARQ window size
//	byte 15     : max ARQ data NACK max gap
//	bytes 16-17 : min compression min size
//	byte 18     : min ARQ initial RTO (scaled 0..255 => 0.05..1.00s)
type SessionAcceptPayload struct {
	SessionID           uint8
	CompressionPair     uint8
	VerifyCode          [4]byte
	ClientPolicy        SessionAcceptClientPolicy
	HasClientPolicySync bool
}

type SessionAcceptClientSettings struct {
	PacketDuplicationCount      int
	SetupPacketDuplicationCount int
	MaxUploadMTU                int
	MaxDownloadMTU              int
	RXTXWorkers                 int
	PingAggressiveInterval      float64
	MaxPacketsPerBatch          int
	ARQWindowSize               int
	ARQDataNackMaxGap           int
	CompressionMinSize          int
	ARQInitialRTOSeconds        float64
	ARQControlInitialRTOSeconds float64
	ARQMaxRTOSeconds            float64
	ARQControlMaxRTOSeconds     float64
}

// SessionAcceptClientPolicy defines the server-side client limits/minimums
// carried in the encrypted v1 ACCEPT policy, as a 13-byte block:
//
//	byte 0      : lower nibble = max packet duplication, upper nibble = max setup duplication
//	byte 1      : max upload MTU (uint8)
//	bytes 2-3   : max download MTU (uint16, big endian)
//	byte 4      : max RX/TX workers (uint8)
//	byte 5      : min ping aggressive interval, scaled 0..255 => 0.05..1.00 seconds
//	byte 6      : max packets per batch (uint8)
//	bytes 7-8   : max ARQ window size (uint16, big endian)
//	byte 9      : max ARQ data NACK max gap (uint8)
//	bytes 10-11 : min compression min-size (uint16, big endian)
//	byte 12     : min ARQ initial RTO, scaled 0..255 => 0.05..1.00 seconds
type SessionAcceptClientPolicy struct {
	MaxPacketDuplicationCount int
	MaxSetupDuplicationCount  int
	MaxUploadMTU              int
	MaxDownloadMTU            int
	MaxRxTxWorkers            int
	MinPingAggressiveInterval float64
	MaxPacketsPerBatch        int
	MaxARQWindowSize          int
	MaxARQDataNackMaxGap      int
	MinCompressionMinSize     int
	MinARQInitialRTOSeconds   float64
}

// EncodeSessionAcceptV1Policy encodes the policy carried after the encrypted
// session ID in the v1 ACCEPT.
func EncodeSessionAcceptV1Policy(payload SessionAcceptPayload) []byte {
	buf := make([]byte, SessionAcceptV1PolicySize)
	buf[0] = payload.CompressionPair
	copy(buf[1:5], payload.VerifyCode[:])
	policy := EncodeSessionAcceptClientPolicy(payload.ClientPolicy)
	copy(buf[5:], policy[:])
	return buf
}

func DecodeSessionAcceptV1Policy(sessionID uint8, policy []byte) (SessionAcceptPayload, error) {
	if len(policy) != SessionAcceptV1PolicySize {
		return SessionAcceptPayload{}, fmt.Errorf("invalid v1 session policy length: got=%d want=%d", len(policy), SessionAcceptV1PolicySize)
	}
	clientPolicy, err := DecodeSessionAcceptClientPolicy(policy[5:])
	if err != nil {
		return SessionAcceptPayload{}, err
	}
	result := SessionAcceptPayload{
		SessionID:           sessionID,
		CompressionPair:     policy[0],
		ClientPolicy:        clientPolicy,
		HasClientPolicySync: true,
	}
	copy(result.VerifyCode[:], policy[1:5])
	return result, nil
}

func ApplySessionAcceptClientPolicy(current SessionAcceptClientSettings, policy SessionAcceptClientPolicy) SessionAcceptClientSettings {
	current.PacketDuplicationCount = clampInt(current.PacketDuplicationCount, 1, maxInt(policy.MaxPacketDuplicationCount, 1))
	current.SetupPacketDuplicationCount = clampInt(
		current.SetupPacketDuplicationCount,
		current.PacketDuplicationCount,
		maxInt(policy.MaxSetupDuplicationCount, current.PacketDuplicationCount),
	)

	current.MaxUploadMTU = clampInt(current.MaxUploadMTU, 1, maxInt(policy.MaxUploadMTU, 1))
	current.MaxDownloadMTU = clampInt(current.MaxDownloadMTU, 1, maxInt(policy.MaxDownloadMTU, 1))
	current.RXTXWorkers = clampInt(current.RXTXWorkers, 1, maxInt(policy.MaxRxTxWorkers, 1))
	current.PingAggressiveInterval = clampFloat64(current.PingAggressiveInterval, policy.MinPingAggressiveInterval, 30.0)
	current.MaxPacketsPerBatch = clampInt(current.MaxPacketsPerBatch, 1, maxInt(policy.MaxPacketsPerBatch, 1))
	current.ARQWindowSize = clampInt(current.ARQWindowSize, 1, maxInt(policy.MaxARQWindowSize, 1))
	current.ARQDataNackMaxGap = clampInt(current.ARQDataNackMaxGap, 0, maxInt(policy.MaxARQDataNackMaxGap, 0))
	current.CompressionMinSize = maxInt(current.CompressionMinSize, maxInt(policy.MinCompressionMinSize, 1))
	current.ARQInitialRTOSeconds = clampFloat64(current.ARQInitialRTOSeconds, policy.MinARQInitialRTOSeconds, current.ARQMaxRTOSeconds)
	current.ARQControlInitialRTOSeconds = clampFloat64(current.ARQControlInitialRTOSeconds, policy.MinARQInitialRTOSeconds, current.ARQControlMaxRTOSeconds)
	return current
}

func EncodeSessionAcceptClientPolicy(policy SessionAcceptClientPolicy) [SessionAcceptPolicyPayloadSize]byte {
	var payload [SessionAcceptPolicyPayloadSize]byte

	payload[0] = byte((clampInt(policy.MaxSetupDuplicationCount, 0, 15) << 4) |
		clampInt(policy.MaxPacketDuplicationCount, 0, 15))
	payload[1] = byte(clampInt(policy.MaxUploadMTU, 0, 0xFF))
	binary.BigEndian.PutUint16(payload[2:4], uint16(clampInt(policy.MaxDownloadMTU, 0, 0xFFFF)))
	payload[4] = byte(clampInt(policy.MaxRxTxWorkers, 0, 0xFF))
	payload[5] = EncodeSessionScaledByte(policy.MinPingAggressiveInterval)
	payload[6] = byte(clampInt(policy.MaxPacketsPerBatch, 0, 0xFF))
	binary.BigEndian.PutUint16(payload[7:9], uint16(clampInt(policy.MaxARQWindowSize, 0, 0xFFFF)))
	payload[9] = byte(clampInt(policy.MaxARQDataNackMaxGap, 0, 0xFF))
	binary.BigEndian.PutUint16(payload[10:12], uint16(clampInt(policy.MinCompressionMinSize, 0, 0xFFFF)))
	payload[12] = EncodeSessionScaledByte(policy.MinARQInitialRTOSeconds)

	return payload
}

func DecodeSessionAcceptClientPolicy(payload []byte) (SessionAcceptClientPolicy, error) {
	if len(payload) < SessionAcceptPolicyPayloadSize {
		return SessionAcceptClientPolicy{}, fmt.Errorf("session accept policy payload too short: got=%d want=%d", len(payload), SessionAcceptPolicyPayloadSize)
	}

	return SessionAcceptClientPolicy{
		MaxPacketDuplicationCount: int(payload[0] & 0x0F),
		MaxSetupDuplicationCount:  int((payload[0] >> 4) & 0x0F),
		MaxUploadMTU:              int(payload[1]),
		MaxDownloadMTU:            int(binary.BigEndian.Uint16(payload[2:4])),
		MaxRxTxWorkers:            int(payload[4]),
		MinPingAggressiveInterval: DecodeSessionScaledByte(payload[5]),
		MaxPacketsPerBatch:        int(payload[6]),
		MaxARQWindowSize:          int(binary.BigEndian.Uint16(payload[7:9])),
		MaxARQDataNackMaxGap:      int(payload[9]),
		MinCompressionMinSize:     int(binary.BigEndian.Uint16(payload[10:12])),
		MinARQInitialRTOSeconds:   DecodeSessionScaledByte(payload[12]),
	}, nil
}

func EncodeSessionScaledByte(value float64) uint8 {
	clamped := clampFloat64(value, SessionPolicyScaledMin, SessionPolicyScaledMax)
	if SessionPolicyScaledMax <= SessionPolicyScaledMin {
		return 0
	}

	normalized := (clamped - SessionPolicyScaledMin) / (SessionPolicyScaledMax - SessionPolicyScaledMin)
	return uint8(math.Round(normalized * 255.0))
}

func DecodeSessionScaledByte(value uint8) float64 {
	normalized := float64(value) / 255.0
	return SessionPolicyScaledMin + normalized*(SessionPolicyScaledMax-SessionPolicyScaledMin)
}

func clampFloat64(value float64, minValue float64, maxValue float64) float64 {
	if value < minValue {
		return minValue
	}

	if value > maxValue {
		return maxValue
	}

	return value
}

func clampInt(value int, minValue int, maxValue int) int {
	if value < minValue {
		return minValue
	}

	if value > maxValue {
		return maxValue
	}

	return value
}

func maxInt(a int, b int) int {
	if a > b {
		return a
	}

	return b
}
