package consensus

// NewSequenceEvent is posted to wake the worker for the next block-building
// cycle. Most engines emit it only when a new sequence (block number) starts.
// Engines with lazy proposer rebuilds may also use RoundChange=true to request
// an immediate rebuild for the current sequence after becoming proposer.
type NewSequenceEvent struct {
	// RoundChange marks a proposer rebuild requested after becoming proposer
	// for the current sequence via round change. BFT workers use this to skip
	// the ideal-block-time wait when the round change itself already consumed
	// the sequencing delay.
	RoundChange bool
}
