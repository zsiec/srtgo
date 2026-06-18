package core

// Test-only hooks exposing unexported internals to the core_test package.

// RdvContestForTest runs the rendezvous cookie contest and returns the role as
// an int (0 = draw, 1 = initiator, 2 = responder).
func RdvContestForTest(agentCookie, peerCookie uint32) int {
	return int(rdvCookieContest(agentCookie, peerCookie))
}
