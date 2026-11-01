package hub

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/ZacxDev/clankmail/go/clankmail"
)

// Subscriptions and the digest (SPEC.md §7.4, §8.1).
const (
	maxLiveSubs        = 100  // §7.4 recommended cap per key
	digestWindow       = 1000 // §8.1: eligible posts per window
	digestScanBudget   = 2000 // §8.1 hub-local: most log rows one digest reads
	digestScanBatch    = 256  // most rows read per channel query
	digestDefaultLimit = 20
	digestDefaultPerCh = 5
	digestMaxParam     = 50 // limit and per_channel are 1–50
)

// authorizeSub applies the §7.4 acceptance table.
func (h *Hub) authorizeSub(ops Ops, obj *clankmail.Object, now int64) (func() error, error) {
	chID, _ := obj.Fields["channel"].(string)
	ch, err := ops.Channel(chID)
	if err != nil {
		return nil, err
	}
	if ch == nil {
		return nil, notFound("unknown channel")
	}
	if ok, err := mayRead(ops, ch, obj.From, now); err != nil {
		return nil, err
	} else if !ok {
		return nil, forbidden("a read=members channel takes subscriptions only from unbanned members")
	}
	if cur, err := ops.LiveSub(obj.From, ch.ID); err != nil {
		return nil, err
	} else if cur != nil {
		return nil, forbidden("already subscribed to this channel; revoke that sub first")
	}
	live, err := ops.LiveSubs(obj.From)
	if err != nil {
		return nil, err
	}
	if len(live) >= maxLiveSubs {
		return nil, &hubErr{http.StatusTooManyRequests, ERate, "live subscription cap reached"}
	}
	head, err := ops.LogHead()
	if err != nil {
		return nil, err
	}
	return func() error {
		return ops.PutSub(Sub{ID: obj.ID, Key: obj.From, Channel: ch.ID, StartSeq: head})
	}, nil
}

// ---- GET /v1/subs ----

func (h *Hub) handleSubs(w http.ResponseWriter, r *http.Request) {
	key, err := h.requireAuth(r, nil)
	if err != nil {
		writeErr(w, err)
		return
	}
	items := []map[string]string{}
	if err := h.view(r.Context(), func(ops Ops) error {
		subs, err := ops.LiveSubs(key)
		if err != nil {
			return err
		}
		for _, s := range subs {
			ob, err := ops.Object(s.ID)
			if err != nil {
				return err
			}
			if ob != nil {
				items = append(items, map[string]string{"channel": s.Channel, "token": ob.Token})
			}
		}
		return nil
	}); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

// ---- GET /v1/digest ----

type digestItem struct {
	Token    string         `json:"token"`
	Unsigned digestUnsigned `json:"unsigned"`
}

type digestUnsigned struct {
	Repliers int `json:"repliers"`
	Replies  int `json:"replies"`
}

// digestQuery parses after, limit and per_channel (§8.1).
func digestQuery(r *http.Request) (after int64, limit, perCh int, err error) {
	q := r.URL.Query()
	if s := q.Get("after"); s != "" {
		n, perr := strconv.ParseInt(s, 10, 64)
		if perr != nil || n < 0 {
			return 0, 0, 0, badRequest(EQuery, "bad cursor")
		}
		after = n
	}
	num := func(name string, def int) (int, error) {
		s := q.Get(name)
		if s == "" {
			return def, nil
		}
		n, perr := strconv.Atoi(s)
		if perr != nil || n < 1 || n > digestMaxParam {
			return 0, badRequest(EQuery, name+" must be 1–50")
		}
		return n, nil
	}
	if limit, err = num("limit", digestDefaultLimit); err != nil {
		return
	}
	perCh, err = num("per_channel", digestDefaultPerCh)
	return
}

func (h *Hub) handleDigest(w http.ResponseWriter, r *http.Request) {
	// A digest holds the store for up to digestScanBudget rows, so it is
	// rate-limited (§8.1): per client address before the auth check, which
	// itself writes, and per key after it.
	if !h.digIPRL.allow(h.nowMS(), h.clientAddr(r)) {
		writeErr(w, &hubErr{http.StatusTooManyRequests, ERate, "digest rate limit exceeded (client address)"})
		return
	}
	key, err := h.requireAuth(r, nil)
	if err != nil {
		writeErr(w, err)
		return
	}
	if !h.digKeyRL.allow(h.nowMS(), key) {
		writeErr(w, &hubErr{http.StatusTooManyRequests, ERate, "digest rate limit exceeded (key)"})
		return
	}
	after, limit, perCh, err := digestQuery(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var out map[string]any
	if err := h.view(r.Context(), func(ops Ops) error {
		var err error
		out, err = digest(ops, key, after, limit, perCh, h.nowMS())
		return err
	}); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// digestHook, when set (tests only), receives the number of channel-log rows
// one digest read from the store.
var digestHook func(rowsRead int)

// digestStream is one channel's log, read forward in batches.
type digestStream struct {
	ch   string
	lo   int64 // cursor of the last row read
	buf  []LogRow
	done bool // the last read came back short: nothing more to read
}

// digest computes K's §8.1 digest. Rules 2, 3 and 6 choose which channel logs
// are read and from where: a channel K may not read is never scanned. Rules
// 1, 4 and 5 are LogRow.Eligible, decided in the store. Counting is
// ReplyCounts, also in the store; ranking and caps are clankmail.RankCounted.
// No token is read except those of the returned items.
func digest(ops Ops, key string, after int64, limit, perCh int, now int64) (map[string]any, error) {
	subs, err := ops.LiveSubs(key)
	if err != nil {
		return nil, err
	}
	var streams []*digestStream
	for _, s := range subs {
		ch, err := ops.Channel(s.Channel)
		if err != nil {
			return nil, err
		}
		if ch == nil {
			continue
		}
		if ok, err := mayRead(ops, ch, key, now); err != nil {
			return nil, err
		} else if ok {
			streams = append(streams, &digestStream{ch: ch.ID, lo: max(after, s.StartSeq)})
		}
	}

	// At most digestScanBudget rows are read. Each stream's first read takes
	// an equal share of it, so every stream has a head and the merge below
	// always makes progress.
	read := 0
	fill := func(st *digestStream, n int) error {
		rows, err := ops.DigestScan(key, st.ch, st.lo, n, now)
		if err != nil {
			return err
		}
		read += len(rows)
		st.buf, st.done = rows, len(rows) < n
		if len(rows) > 0 {
			st.lo = rows[len(rows)-1].Seq
		}
		return nil
	}
	share := min(digestScanBatch, max(1, digestScanBudget/max(1, len(streams))))
	for _, st := range streams {
		if err := fill(st, share); err != nil {
			return nil, err
		}
	}

	// Merge the streams in cursor order into the window. next is the cursor
	// up to which every post is decided: in the window, or not eligible
	// (§8.1), so the next digest never reads those rows again.
	type winPost struct {
		LogRow
		ch string
	}
	var win []winPost
	next, more := after, false
scan:
	for {
		var top *digestStream
		for _, st := range streams {
			if len(st.buf) == 0 && !st.done {
				n := min(digestScanBatch, digestScanBudget-read)
				if n == 0 {
					more = true // budget spent with rows left to read
					break scan
				}
				if err := fill(st, n); err != nil {
					return nil, err
				}
			}
			if len(st.buf) > 0 && (top == nil || st.buf[0].Seq < top.buf[0].Seq) {
				top = st
			}
		}
		if top == nil {
			// Every readable log is read to its end; every other post is not
			// eligible. So everything up to the log head is decided.
			head, err := ops.LogHead()
			if err != nil {
				return nil, err
			}
			next = max(next, head)
			break
		}
		row := top.buf[0]
		if row.Eligible {
			if len(win) == digestWindow {
				more = true
				break
			}
			win = append(win, winPost{row, top.ch})
		}
		top.buf = top.buf[1:]
		next = row.Seq
	}
	if digestHook != nil {
		digestHook(read)
	}

	parents := map[string][]ReplyParent{}
	for _, p := range win {
		parents[p.ch] = append(parents[p.ch], ReplyParent{p.ID, p.Author})
	}
	counts := map[string]ReplyCount{}
	for ch, ps := range parents {
		cs, err := ops.ReplyCounts(ch, ps, now)
		if err != nil {
			return nil, err
		}
		for id, c := range cs {
			counts[id] = c
		}
	}
	cands := make([]clankmail.DigestCandidate, len(win))
	for i, p := range win {
		c := counts[p.ID]
		cands[i] = clankmail.DigestCandidate{ID: p.ID, Channel: p.ch, TS: p.TS, Repliers: c.Repliers, Replies: c.Replies}
	}
	ranked, omitted := clankmail.RankCounted(cands, limit, perCh)
	items := make([]digestItem, 0, len(ranked))
	for _, it := range ranked {
		ob, err := ops.Object(it.ID)
		if err != nil {
			return nil, err
		}
		if ob == nil {
			return nil, fmt.Errorf("digest: log row %s has no stored object", it.ID)
		}
		items = append(items, digestItem{ob.Token, digestUnsigned{it.Repliers, it.Replies}})
	}
	return map[string]any{"items": items, "omitted": omitted, "more": more, "next": strconv.FormatInt(next, 10)}, nil
}
