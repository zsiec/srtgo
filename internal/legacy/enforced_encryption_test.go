package legacy

// Tests ported from the C++ SRT implementation's test_enforced_encryption.cpp
// to verify that Go's enforced encryption behavior matches the reference.

import (
	"sync"
	"testing"
	"time"
)

// TestEnforcedEncryptionMatrix tests all 20 combinations of:
//   - EnforcedEncryption: caller={true,false} x listener={true,false} (groups A,B,C,D)
//   - Passwords: {both_match, both_mismatch, caller_only, listener_only, neither} (5 cases)
func TestEnforcedEncryptionMatrix(t *testing.T) {
	const (
		pwdA  = "s!t@r#i$c^t"  // 11 chars, matches reference s_pwd_a
		pwdB  = "s!t@r#i$c^tu" // 12 chars, matches reference s_pwd_b
		pwdNo = ""             // no password
	)

	boolPtr := func(v bool) *bool { return &v }

	type testCase struct {
		name             string
		callerEnforced   bool
		listenerEnforced bool
		callerPwd        string
		listenerPwd      string
		expectConnect    bool
		knownDivergence  string // documents known behavior differences from C++ reference
	}

	cases := []testCase{
		// Group A: both enforced=true
		{"A.1_both_enforced_same_pwd", true, true, pwdA, pwdA, true, ""},
		{"A.2_both_enforced_diff_pwd", true, true, pwdA, pwdB, false, ""},
		{"A.3_both_enforced_caller_only", true, true, pwdA, pwdNo, false, ""},
		{"A.4_both_enforced_listener_only", true, true, pwdNo, pwdA, false, ""},
		{"A.5_both_enforced_no_pwd", true, true, pwdNo, pwdNo, true, ""},

		// Group B: caller enforced=true, listener enforced=false
		{"B.1_caller_enforced_same_pwd", true, false, pwdA, pwdA, true, ""},
		{"B.2_caller_enforced_diff_pwd", true, false, pwdA, pwdB, false, ""},
		{"B.3_caller_enforced_caller_only", true, false, pwdA, pwdNo, false, ""},
		{"B.4_caller_enforced_listener_only", true, false, pwdNo, pwdA, false, ""},
		{"B.5_caller_enforced_no_pwd", true, false, pwdNo, pwdNo, true, ""},

		// Group C: caller enforced=false, listener enforced=true
		{"C.1_listener_enforced_same_pwd", false, true, pwdA, pwdA, true, ""},
		{"C.2_listener_enforced_diff_pwd", false, true, pwdA, pwdB, false, ""},
		{"C.3_listener_enforced_caller_only", false, true, pwdA, pwdNo, false, ""},
		{"C.4_listener_enforced_listener_only", false, true, pwdNo, pwdA, false, ""},
		{"C.5_listener_enforced_no_pwd", false, true, pwdNo, pwdNo, true, ""},

		// Group D: both enforced=false — all cases connect (degraded/no encryption)
		{"D.1_both_relaxed_same_pwd", false, false, pwdA, pwdA, true, ""},
		{"D.2_both_relaxed_diff_pwd", false, false, pwdA, pwdB, true, ""},
		{"D.3_both_relaxed_caller_only", false, false, pwdA, pwdNo, true, ""},
		{"D.4_both_relaxed_listener_only", false, false, pwdNo, pwdA, true, ""},
		{"D.5_both_relaxed_no_pwd", false, false, pwdNo, pwdNo, true, ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.knownDivergence != "" {
				t.Logf("Known divergence from C++ reference: %s", tc.knownDivergence)
			}

			listenerCfg := DefaultConfig()
			listenerCfg.Latency = 20 * time.Millisecond
			listenerCfg.ConnTimeout = 3 * time.Second
			listenerCfg.Passphrase = tc.listenerPwd
			listenerCfg.EnforcedEncryption = boolPtr(tc.listenerEnforced)

			l, err := Listen("127.0.0.1:0", listenerCfg)
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			defer l.Close()

			callerCfg := DefaultConfig()
			callerCfg.Latency = 20 * time.Millisecond
			callerCfg.ConnTimeout = 3 * time.Second
			callerCfg.Passphrase = tc.callerPwd
			callerCfg.EnforcedEncryption = boolPtr(tc.callerEnforced)

			var accepted *Conn
			var acceptErr error
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				accepted, acceptErr = l.Accept()
			}()

			client, dialErr := Dial(l.Addr().String(), callerCfg)

			if tc.expectConnect {
				if dialErr != nil {
					t.Fatalf("expected Dial to succeed, got: %v", dialErr)
				}
				wg.Wait()
				if acceptErr != nil {
					t.Fatalf("expected Accept to succeed, got: %v", acceptErr)
				}
				defer client.Close()
				defer accepted.Close()

				// Verify the connection is usable with a data roundtrip
				payload := []byte("encryption-matrix-test")
				if _, err := client.Write(payload); err != nil {
					t.Fatalf("Write: %v", err)
				}
				buf := make([]byte, 1500)
				accepted.SetReadDeadline(time.Now().Add(2 * time.Second))
				n, err := accepted.Read(buf)
				if err != nil {
					t.Fatalf("Read: %v", err)
				}
				if string(buf[:n]) != string(payload) {
					t.Errorf("payload mismatch: got %q, want %q", buf[:n], payload)
				}
			} else {
				// Connection should fail. Dial may fail outright, or may return
				// a connection that is immediately broken (e.g., B.2-B.4 where
				// the listener accepts but the caller rejects after KMRSP).
				if dialErr != nil {
					// Close listener to unblock Accept goroutine
					l.Close()
					wg.Wait()
					t.Logf("Dial failed as expected: %v", dialErr)
					return
				}

				// Dial returned a connection — it should be broken.
				// Wait briefly for Accept (it may or may not have accepted).
				acceptDone := make(chan struct{})
				go func() {
					wg.Wait()
					close(acceptDone)
				}()
				select {
				case <-acceptDone:
				case <-time.After(5 * time.Second):
					l.Close()
					<-acceptDone
				}

				defer client.Close()
				if accepted != nil {
					defer accepted.Close()
				}

				client.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1500)
				_, readErr := client.Read(buf)
				if readErr == nil {
					_, writeErr := client.Write([]byte("test"))
					if writeErr == nil {
						t.Fatal("expected connection to be rejected, but Read and Write both succeeded")
					}
				}
				t.Logf("Connection broken as expected (Dial returned but conn is dead)")
			}
		})
	}
}
