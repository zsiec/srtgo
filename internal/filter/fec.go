package filter

import (
	"encoding/binary"

	seqpkg "github.com/zsiec/srtgo/internal/seq"
)

// fecMaxRcvHistory is the maximum number of FEC matrix series that the receiver
// tracks. Groups older than this are discarded.
const fecMaxRcvHistory = 10

// RecoveredPacket holds a packet recovered by FEC XOR rebuild.
type RecoveredPacket struct {
	SeqNo         uint32
	Timestamp     uint32
	EncFlag       uint8
	Retransmitted bool // true if this should be marked as retransmitted (REXMIT flag)
	Payload       []byte
}

// fecGroup tracks the XOR accumulation state for one FEC group (row or column).
type fecGroup struct {
	base          uint32 // first sequence number in group
	step          int    // distance between consecutive members (1 for row, cols for column)
	collected     int    // number of data packets clipped so far
	hasFEC        bool   // FEC control packet received (receiver only)
	lengthClip    uint16 // XOR of packet lengths (host byte order)
	flagClip      uint8  // XOR of encryption key flags
	timestampClip uint32 // XOR of timestamps
	payloadClip   []byte // XOR of payloads (padded to payloadSize)
}

func newGroup(base uint32, step int, payloadSize int) fecGroup {
	return fecGroup{
		base:        base,
		step:        step,
		payloadClip: make([]byte, payloadSize),
	}
}

func (g *fecGroup) reset(newBase uint32) {
	g.base = newBase
	g.collected = 0
	g.hasFEC = false
	g.lengthClip = 0
	g.flagClip = 0
	g.timestampClip = 0
	clear(g.payloadClip)
}

// clipData XORs a packet's metadata and payload into the group accumulator.
func (g *fecGroup) clipData(length uint16, flags uint8, timestamp uint32, payload []byte) {
	g.lengthClip ^= length
	g.flagClip ^= flags
	g.timestampClip ^= timestamp

	// XOR payload bytes; short payloads are implicitly zero-padded.
	for i := 0; i < len(payload) && i < len(g.payloadClip); i++ {
		g.payloadClip[i] ^= payload[i]
	}
	// Remaining bytes XOR with 0 (no-op).
}

// clipPacket clips a data packet into the group.
func (g *fecGroup) clipPacket(payloadLen int, encFlag uint8, timestamp uint32, payload []byte) {
	g.clipData(uint16(payloadLen), encFlag, timestamp, payload)
}

// clipFECPacket clips an FEC control packet into the group (for receiver rebuild).
// The FEC packet payload starts with the 4-byte FEC header.
func (g *fecGroup) clipFECPacket(timestamp uint32, fecPayload []byte) {
	if len(fecPayload) < ExtraHeaderSize {
		return
	}
	flagClip := fecPayload[1]
	lengthClip := binary.BigEndian.Uint16(fecPayload[2:4])
	clipPayload := fecPayload[ExtraHeaderSize:]
	g.clipData(lengthClip, flagClip, timestamp, clipPayload)
}

// ------- Sender -------

// FECSender generates FEC control packets from a stream of data packets.
type FECSender struct {
	cfg         Config
	payloadSize int

	row  fecGroup   // current horizontal (row) group
	cols []fecGroup // column groups (one per column in the current series)

	sndBase   uint32 // base seqno of the current row group
	lastSeqNo uint32 // seqno of the last data packet fed

	// pendingFEC holds FEC packets ready for emission.
	pendingFEC []pendingFECPacket
}

type pendingFECPacket struct {
	data       []byte
	groupIndex int8
	timestamp  uint32
	seqNo      uint32 // seqno of last data packet in the group (FEC shares this seqno)
}

// NewFECSender creates a new FEC sender with the given config and ISN.
// payloadSize is the max data payload per packet (e.g., 1316 for live).
func NewFECSender(cfg Config, payloadSize int, isn uint32) *FECSender {
	s := &FECSender{
		cfg:         cfg,
		payloadSize: payloadSize,
		sndBase:     isn,
		lastSeqNo:   isn,
	}

	s.row = newGroup(isn, 1, payloadSize)

	if cfg.Rows > 1 {
		s.cols = make([]fecGroup, cfg.Cols)
		s.configureColumns(isn)
	}

	return s
}

// configureColumns initializes column groups starting from isn.
func (s *FECSender) configureColumns(isn uint32) {
	if s.cfg.Layout == LayoutEven {
		for i := range s.cfg.Cols {
			base := seqAdd(isn, uint32(i))
			s.cols[i] = newGroup(base, s.sizeRow(), s.payloadSize)
		}
		return
	}

	// Staircase layout: column bases staggered by (1 + sizeRow) per column,
	// wrapping after numberRows columns.
	offset := 0
	for i := range s.cfg.Cols {
		base := seqAdd(isn, uint32(offset))
		s.cols[i] = newGroup(base, s.sizeRow(), s.payloadSize)

		if i%s.cfg.Rows == s.cfg.Rows-1 {
			offset = i + 1
		} else {
			offset += 1 + s.sizeRow()
		}
	}
}

func (s *FECSender) sizeRow() int    { return s.cfg.Cols }
func (s *FECSender) sizeCol() int    { return s.cfg.Rows }
func (s *FECSender) matrixSize() int { return s.cfg.Cols * s.cfg.Rows }

// FeedSource clips a data packet into the appropriate row and column groups.
// Must be called for each data packet in sequence order.
func (s *FECSender) FeedSource(seqNo uint32, timestamp uint32, encFlag uint8, payload []byte) {
	s.pendingFEC = s.pendingFEC[:0]
	s.lastSeqNo = seqNo

	baseOff := seqDiff(s.sndBase, seqNo)

	// Check if the horizontal group needs to be closed and reset.
	if baseOff >= s.sizeRow() {
		s.resetRowForNext()
		baseOff = seqDiff(s.sndBase, seqNo)
	}

	// Clip into horizontal group
	s.row.clipPacket(len(payload), encFlag, timestamp, payload)
	s.row.collected++

	// Column feeding (skip if rows == 1, i.e. row-only config)
	if s.sizeCol() >= 2 && s.cols != nil {
		vertGX := baseOff % s.sizeRow()
		if vertGX >= 0 && vertGX < len(s.cols) {
			vertOff := seqDiff(s.cols[vertGX].base, seqNo)

			if vertOff >= 0 {
				// Check if column group needs reset
				vertPos := vertOff / s.sizeRow()
				if vertPos >= s.sizeCol() {
					s.resetColumnForNext(vertGX)
				}
				s.cols[vertGX].clipPacket(len(payload), encFlag, timestamp, payload)
				s.cols[vertGX].collected++
			}
		}
	}

	// Check if any group is ready to emit an FEC packet.
	// Check VERTICAL first, then HORIZONTAL.
	// This is because horizontal reset would shift the row base needed for column index.

	if s.sizeCol() >= 2 && s.cols != nil {
		vertGX := baseOff % s.sizeRow()
		if vertGX >= 0 && vertGX < len(s.cols) && s.cols[vertGX].collected >= s.sizeCol() {
			s.emitFEC(&s.cols[vertGX], int8(vertGX), seqNo)
			s.resetColumnForNext(vertGX)
		}
	}

	if s.row.collected >= s.sizeRow() {
		// Emit row FEC packet (index -1), unless ColsOnly suppresses row FEC.
		if !s.cfg.ColsOnly {
			s.emitFEC(&s.row, -1, seqNo)
		}
		s.resetRowForNext()
	}
}

// emitFEC builds an FEC control packet from a completed group.
// The FEC packet shares the seqno of the last data packet in the group
// (it does NOT consume a new sequence number).
func (s *FECSender) emitFEC(g *fecGroup, groupIndex int8, lastDataSeqNo uint32) {
	// Build FEC payload: [index(1)][flagClip(1)][lengthClip(2)][payloadClip...]
	data := make([]byte, ExtraHeaderSize+s.payloadSize)
	data[0] = byte(groupIndex)
	data[1] = g.flagClip
	binary.BigEndian.PutUint16(data[2:4], g.lengthClip)
	copy(data[ExtraHeaderSize:], g.payloadClip)

	s.pendingFEC = append(s.pendingFEC, pendingFECPacket{
		data:       data,
		groupIndex: groupIndex,
		timestamp:  g.timestampClip,
		seqNo:      lastDataSeqNo,
	})
}

// resetRowForNext resets the horizontal group and advances the base.
func (s *FECSender) resetRowForNext() {
	newBase := seqAdd(s.row.base, uint32(s.sizeRow()))
	s.row.reset(newBase)
	s.sndBase = newBase
}

// resetColumnForNext resets a column group and advances its base.
func (s *FECSender) resetColumnForNext(colIdx int) {
	newBase := seqAdd(s.cols[colIdx].base, uint32(s.matrixSize()))
	s.cols[colIdx].reset(newBase)
}

// PackControlPacket returns the next pending FEC packet, if any.
// Returns the FEC payload data, the group index, the seqno (shared with last data pkt),
// the timestamp, and ok=true if available.
// Call repeatedly after FeedSource until ok=false.
func (s *FECSender) PackControlPacket() (data []byte, groupIndex int8, seqNo uint32, timestamp uint32, ok bool) {
	if len(s.pendingFEC) == 0 {
		return nil, 0, 0, 0, false
	}
	p := s.pendingFEC[0]
	s.pendingFEC = s.pendingFEC[1:]
	return p.data, p.groupIndex, p.seqNo, p.timestamp, true
}

// ------- Receiver -------

// rcvGroup extends fecGroup with receiver-specific state.
type rcvGroup struct {
	fecGroup
	dismissed bool // already collected irrecoverable list
}

// FECReceiver processes incoming packets and recovers lost packets via FEC.
type FECReceiver struct {
	cfg         Config
	payloadSize int

	rowGroups  []rcvGroup // sliding window of row groups
	colGroups  []rcvGroup // deque of column groups: [series0_col0..colN-1, series1_col0..colN-1, ...]
	colSeries  int        // number of column series currently tracked
	colBaseISN uint32     // ISN for computing column series offsets

	cells    map[uint32]bool // received packet tracking
	cellBase uint32          // lowest tracked seqno

	// Rebuilt packets ready for output
	rebuilt []RecoveredPacket

	// Stats
	Supplied uint64 // packets recovered by FEC
	Extra    uint64 // FEC control packets received
}

// NewFECReceiver creates a new FEC receiver.
func NewFECReceiver(cfg Config, payloadSize int, isn uint32) *FECReceiver {
	r := &FECReceiver{
		cfg:         cfg,
		payloadSize: payloadSize,
		cells:       make(map[uint32]bool, cfg.Cols*cfg.Rows),
		cellBase:    isn,
	}

	// Initialize first set of row groups
	initialRows := 2
	if cfg.Rows > 1 {
		initialRows = cfg.Rows + 1
	}
	for i := range initialRows {
		base := seqAdd(isn, uint32(i*cfg.Cols))
		g := rcvGroup{fecGroup: newGroup(base, 1, payloadSize)}
		r.rowGroups = append(r.rowGroups, g)
	}

	// Initialize column groups if 2D
	if cfg.Rows > 1 {
		r.colBaseISN = isn
		r.colGroups = make([]rcvGroup, 0, cfg.Cols*2)
		r.extendColumnSeries(isn)
	}

	return r
}

// extendColumnSeries appends a new column series starting at seriesBase.
// Appends numCols new groups for each new series.
func (r *FECReceiver) extendColumnSeries(seriesBase uint32) {
	if r.cfg.Layout == LayoutEven {
		for i := range r.cfg.Cols {
			base := seqAdd(seriesBase, uint32(i))
			r.colGroups = append(r.colGroups, rcvGroup{fecGroup: newGroup(base, r.cfg.Cols, r.payloadSize)})
		}
	} else {
		// Staircase layout
		offset := 0
		for i := range r.cfg.Cols {
			base := seqAdd(seriesBase, uint32(offset))
			r.colGroups = append(r.colGroups, rcvGroup{fecGroup: newGroup(base, r.cfg.Cols, r.payloadSize)})
			if i%r.cfg.Rows == r.cfg.Rows-1 {
				offset = i + 1
			} else {
				offset += 1 + r.cfg.Cols
			}
		}
	}
	r.colSeries++
}

func (r *FECReceiver) sizeRow() int    { return r.cfg.Cols }
func (r *FECReceiver) sizeCol() int    { return r.cfg.Rows }
func (r *FECReceiver) matrixSize() int { return r.cfg.Cols * r.cfg.Rows }

// Receive processes an incoming packet. Returns:
//   - recovered: packets recovered by FEC
//   - lossReport: sequence numbers to NAK (per ARQ level)
//   - passThrough: true if this is a data packet (deliver to app), false for FEC control packets
func (r *FECReceiver) Receive(seqNo uint32, timestamp uint32, encFlag uint8, msgNo uint32,
	payload []byte) (recovered []RecoveredPacket, lossReport []uint32, passThrough bool) {

	r.rebuilt = r.rebuilt[:0]

	// Dismiss old groups if needed
	r.checkLargeDrop(seqNo)

	if msgNo == 0 {
		// FEC control packet
		r.Extra++
		r.markCell(seqNo, false) // extend cells but don't mark received

		if len(payload) < ExtraHeaderSize {
			return nil, nil, false
		}

		colx := int8(payload[0])
		if colx == -1 {
			// Row (horizontal) FEC
			r.hangHorizontalFEC(seqNo, timestamp, payload)
		} else {
			// Column (vertical) FEC
			r.hangVerticalFEC(seqNo, timestamp, payload, int(colx))

			// Dismiss old column groups past this sequence
			colLosses := r.dismissOldColumns(seqNo)
			if len(colLosses) > 0 && r.cfg.ARQ == ARQOnReq {
				lossReport = append(lossReport, colLosses...)
			}
		}

		// Collect row loss report
		rowLosses := r.collectLossReport()
		lossReport = append(lossReport, rowLosses...)

		return r.rebuilt, lossReport, false
	}

	// Data packet: check if already received (dedup with ARQ)
	cellOff := seqDiff(r.cellBase, seqNo)
	if cellOff < 0 || r.cells[seqNo] {
		return nil, nil, true
	}

	r.markCell(seqNo, true)

	// Clip into horizontal row group
	okH := r.hangHorizontalData(seqNo, timestamp, encFlag, payload)

	// Clip into vertical column group (if 2D)
	okV := true
	if r.cfg.Rows > 1 {
		okV = r.hangVerticalData(seqNo, timestamp, encFlag, payload)

		// Check if any old column groups should be dismissed.
		colLosses := r.dismissOldColumns(seqNo)
		if len(colLosses) > 0 && r.cfg.ARQ == ARQOnReq {
			lossReport = colLosses
		}
	}

	// If both horizontal and vertical reject the packet,
	// unmark the cell to allow correct loss reporting.
	if !okH && !okV {
		r.unmarkCell(seqNo)
	}

	return r.rebuilt, lossReport, true
}

// hangHorizontalData processes a data packet for horizontal groups.
// Returns false if the packet couldn't be placed in any group.
func (r *FECReceiver) hangHorizontalData(seqNo, timestamp uint32, encFlag uint8, payload []byte) bool {
	rowIdx := r.getRowGroupIndex(seqNo)
	if rowIdx < 0 {
		return false
	}

	g := &r.rowGroups[rowIdx]
	g.clipPacket(len(payload), encFlag, timestamp, payload)
	g.collected++

	if g.hasFEC && g.collected == r.sizeRow()-1 {
		lostSeq := r.findLostInRow(g)
		if lostSeq >= 0 {
			tp := groupHoriz
			if r.cfg.Rows <= 1 {
				tp = groupSingle
			}
			r.rebuild(g, uint32(lostSeq), tp)
		}
	}
	return true
}

// hangHorizontalFEC processes a row FEC control packet.
func (r *FECReceiver) hangHorizontalFEC(seqNo, timestamp uint32, fecPayload []byte) {
	rowIdx := r.getRowGroupIndex(seqNo)
	if rowIdx < 0 {
		return
	}

	g := &r.rowGroups[rowIdx]
	if g.hasFEC {
		return // already have FEC for this group
	}

	g.hasFEC = true
	g.clipFECPacket(timestamp, fecPayload)

	if g.collected == r.sizeRow()-1 {
		lostSeq := r.findLostInRow(g)
		if lostSeq >= 0 {
			tp := groupHoriz
			if r.cfg.Rows <= 1 {
				tp = groupSingle
			}
			r.rebuild(g, uint32(lostSeq), tp)
		}
	}
}

// hangVerticalData processes a data packet for vertical groups.
// Returns false if the packet couldn't be placed in any group.
func (r *FECReceiver) hangVerticalData(seqNo, timestamp uint32, encFlag uint8, payload []byte) bool {
	colIdx := r.getColumnGroupIndex(seqNo)
	if colIdx < 0 {
		return false
	}

	g := &r.colGroups[colIdx]
	g.clipPacket(len(payload), encFlag, timestamp, payload)
	g.collected++

	if g.hasFEC && g.collected == r.sizeCol()-1 {
		lostSeq := r.findLostInColumn(g)
		if lostSeq >= 0 {
			r.rebuild(g, uint32(lostSeq), groupVert)
		}
	}
	return true
}

// hangVerticalFEC processes a column FEC control packet.
func (r *FECReceiver) hangVerticalFEC(seqNo, timestamp uint32, fecPayload []byte, colx int) {
	// Use getColumnGroupIndex (not getColumnGroupIndexByColX) so that column
	// groups are auto-advanced when the FEC packet belongs to a later series.
	colIdx := r.getColumnGroupIndex(seqNo)
	if colIdx < 0 {
		return
	}

	g := &r.colGroups[colIdx]
	if g.hasFEC {
		return
	}

	g.hasFEC = true
	g.clipFECPacket(timestamp, fecPayload)

	if g.collected == r.sizeCol()-1 {
		lostSeq := r.findLostInColumn(g)
		if lostSeq >= 0 {
			r.rebuild(g, uint32(lostSeq), groupVert)
		}
	}
}

// groupType distinguishes row vs column for recursive rebuild.
type groupType int

const (
	groupHoriz groupType = iota
	groupVert
	groupSingle // no cross-dimension (row-only config)
)

// rebuild recovers a lost packet from a completed group and attempts recursive recovery.
func (r *FECReceiver) rebuild(g *rcvGroup, seqNo uint32, tp groupType) {
	// The lengthClip is the recovered length (XOR of all lengths = missing length)
	length := g.lengthClip
	if int(length) > r.payloadSize {
		return // corrupted; skip
	}

	rp := RecoveredPacket{
		SeqNo:     seqNo,
		Timestamp: g.timestampClip,
		EncFlag:   g.flagClip,
		Payload:   make([]byte, length),
	}
	copy(rp.Payload, g.payloadClip[:length])

	r.rebuilt = append(r.rebuilt, rp)
	r.Supplied++

	// Mark this packet received
	r.markCell(seqNo, true)

	if tp == groupSingle {
		return
	}

	// Recursive: feed recovered packet into the opposite dimension
	if tp == groupHoriz {
		r.crossRebuildVertical(seqNo, rp)
	} else {
		r.crossRebuildHorizontal(seqNo, rp)
	}
}

// crossRebuildHorizontal clips a recovered packet into its row group and checks for recovery.
func (r *FECReceiver) crossRebuildHorizontal(seqNo uint32, rp RecoveredPacket) {
	rowIdx := r.getRowGroupIndex(seqNo)
	if rowIdx < 0 {
		return
	}

	g := &r.rowGroups[rowIdx]
	g.clipPacket(len(rp.Payload), rp.EncFlag, rp.Timestamp, rp.Payload)
	g.collected++

	if g.hasFEC && g.collected == r.sizeRow()-1 {
		lostSeq := r.findLostInRow(g)
		if lostSeq >= 0 {
			r.rebuild(g, uint32(lostSeq), groupHoriz)
		}
	}
}

// crossRebuildVertical clips a recovered packet into its column group and checks for recovery.
func (r *FECReceiver) crossRebuildVertical(seqNo uint32, rp RecoveredPacket) {
	colIdx := r.getColumnGroupIndex(seqNo)
	if colIdx < 0 {
		return
	}

	g := &r.colGroups[colIdx]
	g.clipPacket(len(rp.Payload), rp.EncFlag, rp.Timestamp, rp.Payload)
	g.collected++

	if g.hasFEC && g.collected == r.sizeCol()-1 {
		lostSeq := r.findLostInColumn(g)
		if lostSeq >= 0 {
			r.rebuild(g, uint32(lostSeq), groupVert)
		}
	}
}

// getRowGroupIndex returns the index into r.rowGroups for a given seqNo, or -1.
func (r *FECReceiver) getRowGroupIndex(seqNo uint32) int {
	if len(r.rowGroups) == 0 {
		return -1
	}

	off := seqDiff(r.rowGroups[0].base, seqNo)
	if off < 0 {
		return -1
	}

	rowIdx := off / r.sizeRow()

	// Bounds check: if too far ahead, the packet is beyond our history window.
	if rowIdx >= fecMaxRcvHistory*r.sizeCol() {
		return -1
	}

	// Extend row groups if needed
	for rowIdx >= len(r.rowGroups) {
		nextBase := seqAdd(r.rowGroups[len(r.rowGroups)-1].base, uint32(r.sizeRow()))
		r.rowGroups = append(r.rowGroups, rcvGroup{fecGroup: newGroup(nextBase, 1, r.payloadSize)})
	}

	return rowIdx
}

// getColumnGroupIndex returns the index into r.colGroups for a given data packet seqNo, or -1.
// Uses a deque of column groups organized as [series0 cols..., series1 cols..., ...].
// When a packet belongs to a later series than currently tracked, new series are
// appended (preserving old groups). Old series are cleaned up by dismissOldColumns.
func (r *FECReceiver) getColumnGroupIndex(seqNo uint32) int {
	if len(r.colGroups) == 0 {
		return -1
	}

	// Compute offset from the ISN base
	off := seqDiff(r.colBaseISN, seqNo)
	if off < 0 {
		return -1
	}

	colIdx := off % r.sizeRow()
	if colIdx < 0 || colIdx >= r.cfg.Cols {
		return -1
	}

	// Compute which series this packet belongs to.
	series := off / r.matrixSize()
	if series < 0 {
		return -1
	}

	// How many series ahead of what we currently track?
	currentMaxSeries := r.colSeries - 1
	if series > currentMaxSeries {
		// Need to extend column groups with new series.
		neededSeries := series - currentMaxSeries
		if r.colSeries+neededSeries > fecMaxRcvHistory {
			return -1
		}
		for range neededSeries {
			nextSeries := r.colSeries
			sbase := seqAdd(r.colBaseISN, uint32(nextSeries*r.matrixSize()))
			r.extendColumnSeries(sbase)
		}
	}

	// The index into colGroups: series * numCols + colIdx
	// But we need to account for series that have been erased from the front.
	// Track via the first series still in the deque.
	firstSeriesOff := seqDiff(r.colBaseISN, r.colGroups[0].base)
	firstSeries := 0
	if firstSeriesOff > 0 {
		firstSeries = firstSeriesOff / r.matrixSize()
	}

	localSeries := series - firstSeries
	if localSeries < 0 {
		return -1 // packet from an already-erased series
	}

	gIdx := localSeries*r.cfg.Cols + colIdx
	if gIdx < 0 || gIdx >= len(r.colGroups) {
		return -1
	}

	return gIdx
}

// getColumnGroupIndexByColX returns the column group index from the FEC header's column index.
// Note: with multi-series column tracking, this only works for the first series.
// Prefer getColumnGroupIndex(seqNo) which handles all series correctly.
func (r *FECReceiver) getColumnGroupIndexByColX(colx int) int {
	if colx < 0 || colx >= len(r.colGroups) {
		return -1
	}
	return colx
}

// findLostInRow finds the single missing sequence number in a row group.
// Returns -1 if none found.
func (r *FECReceiver) findLostInRow(g *rcvGroup) int {
	for i := range r.sizeRow() {
		s := seqAdd(g.base, uint32(i))
		if !r.cells[s] {
			return int(s)
		}
	}
	return -1
}

// findLostInColumn finds the single missing sequence number in a column group.
func (r *FECReceiver) findLostInColumn(g *rcvGroup) int {
	for i := range r.sizeCol() {
		s := seqAdd(g.base, uint32(i*r.sizeRow()))
		if !r.cells[s] {
			return int(s)
		}
	}
	return -1
}

// markCell marks a sequence number with the given state.
func (r *FECReceiver) markCell(seqNo uint32, received bool) {
	if received {
		r.cells[seqNo] = true
	}
}

// unmarkCell removes the received mark for a sequence number.
// Used when both horizontal and vertical processing reject the packet.
func (r *FECReceiver) unmarkCell(seqNo uint32) {
	delete(r.cells, seqNo)
}

// checkLargeDrop dismisses old groups when packets arrive far ahead of current state.
// If the jump exceeds fecMaxRcvHistory matrix series, performs a full reset.
func (r *FECReceiver) checkLargeDrop(seqNo uint32) {
	if len(r.rowGroups) == 0 {
		return
	}

	off := seqDiff(r.rowGroups[0].base, seqNo)
	if off < 0 {
		return
	}

	// Full reset if jump exceeds MAX_RCV_HISTORY series
	matSz := r.matrixSize()
	if matSz > 0 && off/matSz >= fecMaxRcvHistory {
		r.fullReset(seqNo)
		return
	}

	threshold := matSz * 2
	if r.cfg.Rows <= 1 {
		threshold = r.sizeRow() * 2
	}

	for off >= threshold && len(r.rowGroups) > 1 {
		r.rowGroups = r.rowGroups[1:]
		off = seqDiff(r.rowGroups[0].base, seqNo)
		r.cleanCells()
	}

	// Trim old column series from the front of the deque.
	// min_series_history depends on layout:
	//   staircase=4 (columns span across two matrices), even=2
	if r.cfg.Rows > 1 {
		minHistory := 2
		if r.cfg.Layout == LayoutStaircase {
			minHistory = 4
		}
		nCols := r.cfg.Cols
		for r.colSeries > minHistory && len(r.colGroups) > nCols {
			r.colGroups = r.colGroups[nCols:]
			r.colSeries--
		}
	}
}

// fullReset clears all FEC state and reinitializes from a new base sequence.
// Called when a large sequence jump exceeds MAX_RCV_HISTORY.
func (r *FECReceiver) fullReset(seqNo uint32) {
	// Compute the new row base: align to the row boundary containing seqNo
	rowSize := r.sizeRow()
	if rowSize <= 0 {
		rowSize = 1
	}
	// Align base to the start of the row containing seqNo
	newBase := seqNo - uint32(int(seqNo)%rowSize)

	// Reset row groups
	r.rowGroups = r.rowGroups[:0]
	r.rowGroups = append(r.rowGroups, rcvGroup{fecGroup: newGroup(newBase, 1, r.payloadSize)})

	// Reset column groups (multi-series deque)
	r.colGroups = r.colGroups[:0]
	r.colSeries = 0
	r.colBaseISN = newBase
	if r.cfg.Rows > 1 {
		r.extendColumnSeries(newBase)
	}

	// Clear cell map
	clear(r.cells)
}

// dismissOldColumns checks if any column groups have been passed by the current
// sequence and collects irrecoverable losses.
// Called after processing a vertical (column) FEC packet or data packet.
//
// Uses a "mindist" barrier before dismissing columns:
//   - Staircase layout: mindist = 2 * matrix_size (columns span across two matrices)
//   - Even layout: mindist = 1 * matrix_size
//
// This prevents premature dismissal when columns from a staircase arrangement
// still have members arriving in the next matrix.
func (r *FECReceiver) dismissOldColumns(seq uint32) []uint32 {
	if len(r.colGroups) == 0 {
		return nil
	}

	// mindist depends on arrangement
	matSz := r.matrixSize()
	mindist := matSz
	if r.cfg.Layout == LayoutStaircase {
		mindist = matSz * 2
	}

	var losses []uint32
	for i := range r.colGroups {
		g := &r.colGroups[i]
		if g.dismissed {
			continue
		}

		// Overall offset from column base to current seq
		colOffset := seqDiff(g.base, seq)

		// Only dismiss if offset >= mindist
		if colOffset < mindist {
			continue
		}

		// Check if seq is past the last member of this column group.
		// Last member = base + (sizeCol()-1) * step, where step = sizeRow() = Cols.
		lastMemberSpan := (r.sizeCol() - 1) * r.sizeRow()
		lastSeqOffset := colOffset - lastMemberSpan

		if lastSeqOffset < 0 {
			// seq hasn't passed this column's last member yet
			continue
		}

		// Column is past — dismiss and collect irrecoverable losses
		g.dismissed = true
		for sof := 0; sof < g.step*r.sizeCol(); sof += g.step {
			lseq := seqAdd(g.base, uint32(sof))
			if !r.cells[lseq] {
				losses = append(losses, lseq)
			}
		}
	}
	return losses
}

// collectLossReport returns sequence numbers to report as lost based on ARQ level.
// Uses a look-back heuristic: when enough row groups have accumulated,
// the oldest rows (up to len(rowGroups)-2) are dismissed and their irrecoverable
// losses collected. Only if the current sequence has progressed past 1/3 of
// the row size from the group end.
func (r *FECReceiver) collectLossReport() []uint32 {
	if r.cfg.ARQ == ARQAlways || r.cfg.ARQ == ARQNever {
		return nil
	}

	// Need at least 2 row groups
	if len(r.rowGroups) < 2 {
		return nil
	}

	// Determine the latest received sequence to gauge progress
	last := r.rowGroups[len(r.rowGroups)-1]
	latestSeq := seqAdd(last.base, uint32(last.collected))

	// Look-back logic: current = size-2, past = current-1
	// If only 2 rows: check progress in current row (1/3 threshold)
	current := len(r.rowGroups) - 2
	past := current - 1

	if past < 0 {
		// Only 2 rows: check if enough progress in the second row
		seq := r.rowGroups[1].base
		progress := seqDiff(seq, latestSeq)
		if progress <= r.sizeRow()/3 {
			return nil // not enough progress yet
		}
		past = 0
	}

	var losses []uint32
	nRemove := 0
	for i := 0; i <= past; i++ {
		g := &r.rowGroups[i]
		if g.dismissed {
			nRemove++
			continue
		}
		// Collect irrecoverable losses from this row
		for j := range r.sizeRow() {
			seq := seqAdd(g.base, uint32(j))
			if !r.cells[seq] {
				losses = append(losses, seq)
			}
		}
		g.dismissed = true
		nRemove++
	}

	// Actually remove dismissed rows from the front and clean cells
	if nRemove > 0 && nRemove < len(r.rowGroups) {
		r.rowGroups = r.rowGroups[nRemove:]
		r.cleanCells()
	}

	return losses
}

// cleanCells removes cell entries that are older than the current window.
func (r *FECReceiver) cleanCells() {
	if len(r.rowGroups) == 0 {
		return
	}
	newBase := r.rowGroups[0].base
	for seq := range r.cells {
		if seqDiff(newBase, seq) < 0 {
			delete(r.cells, seq)
		}
	}
	r.cellBase = newBase
}

// ------- Helpers -------

// seqDiff returns the signed offset from base to seq using 31-bit SRT
// sequence wrapping (max 0x7FFFFFFF).
func seqDiff(base, s uint32) int {
	return int(seqpkg.Number(base).Distance(seqpkg.Number(s)))
}

// seqAdd returns base + offset with 31-bit wrapping.
func seqAdd(base uint32, offset uint32) uint32 {
	return seqpkg.Number(base).Add(offset).Value()
}
