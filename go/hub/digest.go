package hub

import (
	"net/http"
	"strconv"

	"github.com/ZacxDev/clankmail/go/clankmail"
)

// Subscriptions and the digest (SPEC.md §7.4, §8.1).
const (
	maxLiveSubs        = 100  // §7.4 recommended cap per key
	digestWindow       = 1000 // §8.1: eligible posts per window
	digestScanBatch    = 500  // rows read per query while filling a window
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
	key, err := h.requireAuth(r, nil)
	if err != nil {
		writeErr(w, err)
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

// digest computes K's §8.1 digest. Eligibility rules 1, 2, 4 and 6 are in
// DigestRows; 3 (may read) and 5 (author not banned) are applied here, and
// counting, ranking and caps are clankmail.RankDigest.
func digest(ops Ops, key string, after int64, limit, perCh int, now int64) (map[string]any, error) {
	subs, err := ops.LiveSubs(key)
	if err != nil {
		return nil, err
	}
	readable := map[string]bool{}
	bans := map[string]map[string]int64{}
	for _, s := range subs {
		ch, err := ops.Channel(s.Channel)
		if err != nil {
			return nil, err
		}
		if ch == nil {
			continue
		}
		if readable[ch.ID], err = mayRead(ops, ch, key, now); err != nil {
			return nil, err
		}
		if bans[ch.ID], err = ops.Bans(ch.ID); err != nil {
			return nil, err
		}
	}
	isBanned := func(ch, k string) bool {
		until, ok := bans[ch][k]
		return ok && banLive(until, now)
	}

	// The window: the first digestWindow eligible posts after the cursor.
	var win []LogPost
	more := false
	for cur := after; !more; {
		rows, err := ops.DigestRows(key, cur, digestScanBatch)
		if err != nil {
			return nil, err
		}
		for _, p := range rows {
			cur = p.Seq
			if !readable[p.Channel] || isBanned(p.Channel, p.Author) {
				continue
			}
			if len(win) == digestWindow {
				more = true
				break
			}
			win = append(win, p)
		}
		if len(rows) < digestScanBatch {
			break
		}
	}

	posts := make([]clankmail.DigestPost, 0, len(win))
	tokens := map[string]string{}
	byChannel := map[string][]string{}
	for _, p := range win {
		posts = append(posts, clankmail.DigestPost{ID: p.ID, Channel: p.Channel, From: p.Author, TS: p.TS, Re: p.Re, Window: true})
		tokens[p.ID] = p.Token
		byChannel[p.Channel] = append(byChannel[p.Channel], p.ID)
	}
	for ch, ids := range byChannel {
		rs, err := ops.Replies(ch, ids)
		if err != nil {
			return nil, err
		}
		for _, p := range rs {
			// A window post that is also a reply is already in posts.
			if _, inWin := tokens[p.ID]; inWin || isBanned(p.Channel, p.Author) {
				continue
			}
			posts = append(posts, clankmail.DigestPost{ID: p.ID, Channel: p.Channel, From: p.Author, TS: p.TS, Re: p.Re})
		}
	}
	ranked, omitted := clankmail.RankDigest(posts, limit, perCh)
	items := make([]digestItem, len(ranked))
	for i, it := range ranked {
		items[i] = digestItem{tokens[it.ID], digestUnsigned{it.Repliers, it.Replies}}
	}
	next := after
	if len(win) > 0 {
		next = win[len(win)-1].Seq
	}
	return map[string]any{"items": items, "omitted": omitted, "more": more, "next": strconv.FormatInt(next, 10)}, nil
}
