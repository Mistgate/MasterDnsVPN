package vpnproto

import "testing"

func TestSessionAcceptClientPolicyRoundTrip(t *testing.T) {
	policy := SessionAcceptClientPolicy{
		MaxPacketDuplicationCount: 5,
		MaxSetupDuplicationCount:  6,
		MaxUploadMTU:              150,
		MaxDownloadMTU:            4000,
		MaxRxTxWorkers:            255,
		MinPingAggressiveInterval: 0.05,
		MaxPacketsPerBatch:        10,
		MaxARQWindowSize:          8000,
		MaxARQDataNackMaxGap:      128,
		MinARQInitialRTOSeconds:   0.25,
	}

	payload := EncodeSessionAcceptClientPolicy(policy)
	decoded, err := DecodeSessionAcceptClientPolicy(payload[:])
	if err != nil {
		t.Fatalf("DecodeSessionAcceptClientPolicy returned error: %v", err)
	}

	if decoded.MaxPacketDuplicationCount != policy.MaxPacketDuplicationCount {
		t.Fatalf("unexpected packet duplication: got=%d want=%d", decoded.MaxPacketDuplicationCount, policy.MaxPacketDuplicationCount)
	}
	if decoded.MaxSetupDuplicationCount != policy.MaxSetupDuplicationCount {
		t.Fatalf("unexpected setup duplication: got=%d want=%d", decoded.MaxSetupDuplicationCount, policy.MaxSetupDuplicationCount)
	}
	if decoded.MaxUploadMTU != policy.MaxUploadMTU {
		t.Fatalf("unexpected upload mtu: got=%d want=%d", decoded.MaxUploadMTU, policy.MaxUploadMTU)
	}
	if decoded.MaxDownloadMTU != policy.MaxDownloadMTU {
		t.Fatalf("unexpected download mtu: got=%d want=%d", decoded.MaxDownloadMTU, policy.MaxDownloadMTU)
	}
	if decoded.MaxRxTxWorkers != policy.MaxRxTxWorkers {
		t.Fatalf("unexpected workers: got=%d want=%d", decoded.MaxRxTxWorkers, policy.MaxRxTxWorkers)
	}
	if decoded.MinPingAggressiveInterval < 0.049 || decoded.MinPingAggressiveInterval > 0.051 {
		t.Fatalf("unexpected ping interval: got=%f", decoded.MinPingAggressiveInterval)
	}
	if decoded.MaxPacketsPerBatch != policy.MaxPacketsPerBatch {
		t.Fatalf("unexpected packets per batch: got=%d want=%d", decoded.MaxPacketsPerBatch, policy.MaxPacketsPerBatch)
	}
	if decoded.MaxARQWindowSize != policy.MaxARQWindowSize {
		t.Fatalf("unexpected arq window: got=%d want=%d", decoded.MaxARQWindowSize, policy.MaxARQWindowSize)
	}
	if decoded.MaxARQDataNackMaxGap != policy.MaxARQDataNackMaxGap {
		t.Fatalf("unexpected arq data nack gap: got=%d want=%d", decoded.MaxARQDataNackMaxGap, policy.MaxARQDataNackMaxGap)
	}
	if decoded.MinARQInitialRTOSeconds < 0.245 || decoded.MinARQInitialRTOSeconds > 0.255 {
		t.Fatalf("unexpected arq initial rto: got=%f", decoded.MinARQInitialRTOSeconds)
	}
}

func TestSessionAcceptV1PolicyRoundTrip(t *testing.T) {
	payload := SessionAcceptPayload{
		SessionID:  7,
		VerifyCode: [4]byte{1, 2, 3, 4},
		ClientPolicy: SessionAcceptClientPolicy{
			MaxPacketDuplicationCount: 5,
			MaxSetupDuplicationCount:  6,
			MaxUploadMTU:              150,
			MaxDownloadMTU:            4096,
			MaxRxTxWorkers:            32,
			MinPingAggressiveInterval: 0.10,
			MaxPacketsPerBatch:        10,
			MaxARQWindowSize:          4096,
			MaxARQDataNackMaxGap:      64,
			MinARQInitialRTOSeconds:   0.20,
		},
		HasClientPolicySync: true,
	}

	encoded := EncodeSessionAcceptV1Policy(payload)
	decoded, err := DecodeSessionAcceptV1Policy(payload.SessionID, encoded)
	if err != nil {
		t.Fatalf("DecodeSessionAcceptV1Policy returned error: %v", err)
	}

	if decoded.SessionID != payload.SessionID {
		t.Fatalf("unexpected decoded session id: got=%d want=%d", decoded.SessionID, payload.SessionID)
	}
	if decoded.VerifyCode != payload.VerifyCode {
		t.Fatalf("unexpected verify code: got=%v want=%v", decoded.VerifyCode, payload.VerifyCode)
	}
	if !decoded.HasClientPolicySync {
		t.Fatal("expected client policy sync payload to round-trip")
	}
}
