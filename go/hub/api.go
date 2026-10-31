package hub

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/ZacxDev/clankmail/go/clankmail"
)

const maxJSONBody = 4096

// ---- request auth (§6.4) ----

// authenticate checks the Authorization header against this exact request and
// returns the authenticated key id.
func (h *Hub) authenticate(r *http.Request, body []byte) (string, error) {
	hdr := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(hdr, "ClankMail ")
	if !ok {
		return "", forbidden("authentication required: Authorization: ClankMail <auth token>")
	}
	obj, herr := verify(strings.TrimSpace(tok))
	if herr != nil {
		return "", herr
	}
	if obj.Type != "auth" {
		return "", forbidden("Authorization token must be t=auth")
	}
	now := h.nowMS()
	ts := obj.Fields["ts"].(int64)
	if absDiff(ts, now) > authWindowMS {
		return "", badRequest(EStale, "auth ts outside ±60 s of hub time")
	}
	f := obj.Fields
	sum := sha256.Sum256(body)
	switch {
	case f["hub"] != h.cfg.Name:
		return "", forbidden("auth is for another hub")
	case f["method"] != r.Method:
		return "", forbidden("auth method does not match request")
	case f["path"] != requestPath(r):
		return "", forbidden("auth path does not match request")
	case f["body"] != hex.EncodeToString(sum[:]):
		return "", forbidden("auth body hash does not match request")
	}
	err := h.cfg.Store.Tx(r.Context(), func(ops Ops) error {
		if rev, err := ops.KeyRevoked(obj.From); err != nil {
			return err
		} else if rev {
			return &hubErr{http.StatusForbidden, ERevoked, "auth signer key is revoked"}
		}
		// An id older than the window can never pass the freshness check
		// again, so it need not be remembered.
		if err := ops.PruneAuth(now - authWindowMS); err != nil {
			return err
		}
		fresh, err := ops.UseAuth(obj.ID, ts)
		if err != nil {
			return err
		}
		if !fresh {
			return forbidden("auth token already used")
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return obj.From, nil
}

// requestPath is the path and query exactly as the client sent them on the
// request line, which is what the client signed.
func requestPath(r *http.Request) string {
	if r.RequestURI != "" {
		return r.RequestURI
	}
	return r.URL.RequestURI()
}

// requireAuth is authenticate for endpoints that REQUIRE auth (§6.4, §8):
// every auth failure is 401 E_AUTH, except a revoked signer (403 E_REVOKED)
// and internal errors.
func (h *Hub) requireAuth(r *http.Request, body []byte) (string, error) {
	key, err := h.authenticate(r, body)
	var he *hubErr
	if err != nil && errors.As(err, &he) && he.code != ERevoked && he.status < 500 {
		return "", &hubErr{http.StatusUnauthorized, EAuth, he.detail}
	}
	return key, err
}

// optionalAuth is authenticate for endpoints where auth is optional: any
// failure (or no header) makes the requester anonymous, returned as "".
func (h *Hub) optionalAuth(r *http.Request) string {
	if r.Header.Get("Authorization") == "" {
		return ""
	}
	key, err := h.authenticate(r, nil)
	if err != nil {
		return ""
	}
	return key
}

// ---- helpers ----

func readBody(r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil || len(b) > maxJSONBody {
		return nil, badRequest(clankmail.ESize, "request body too large")
	}
	return b, nil
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// validID applies the §2 canonical decoding rule to a prefixed 32-byte id.
func validID(prefix, s string) bool {
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return false
	}
	b, err := b32.DecodeString(strings.ToUpper(rest))
	return err == nil && len(b) == 32 && clankmail.B32(b) == rest
}

// page parses after= and limit= into a cursor and page size.
func page(r *http.Request) (int64, int, error) {
	var after int64
	if s := r.URL.Query().Get("after"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 0 {
			return 0, 0, badRequest(EQuery, "bad cursor")
		}
		after = n
	}
	limit := defaultLimit
	if s := r.URL.Query().Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > maxPageLimit {
			return 0, 0, badRequest(EQuery, "limit must be 1–200")
		}
		limit = n
	}
	return after, limit, nil
}

type item struct {
	Cursor string `json:"cursor"`
	Token  string `json:"token"`
	Thread string `json:"thread,omitempty"` // derived, unsigned (§7.2)
}

func pageResponse(entries []Entry, after int64) map[string]any {
	items := make([]item, len(entries))
	next := after
	for i, e := range entries {
		items[i] = item{strconv.FormatInt(e.Seq, 10), e.Token, e.Thread}
		next = e.Seq
	}
	return map[string]any{"items": items, "next": strconv.FormatInt(next, 10)}
}

func (h *Hub) view(ctx context.Context, fn func(Ops) error) error { return h.cfg.Store.Tx(ctx, fn) }

// ---- GET /v1/objects/{m_id} ----

func (h *Hub) handleObject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validID("m_", id) {
		writeErr(w, notFound("no such object"))
		return
	}
	var ob *Obj
	var ch *Channel
	var removed bool
	err := h.view(r.Context(), func(ops Ops) error {
		var err error
		if ob, err = ops.Object(id); err != nil || ob == nil || ob.Channel == "" {
			return err
		}
		if ch, err = ops.Channel(ob.Channel); err != nil || ob.Type != "msg" {
			return err
		}
		_, removed, _, err = ops.LogEntry(ob.Channel, ob.ID)
		return err
	})
	if err == nil && ob == nil {
		err = notFound("no such object")
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	// §8: identity objects and manifests are public; so is everything in a
	// read=public channel except a post hidden by remove.
	public := ob.Type == "channel" || ob.Channel == "" && ob.Type != "msg" || ch != nil && ch.Read == "public"
	if removed {
		public = false
	}
	if !public {
		// Every refusal of a private object is a 404, including missing or
		// failed auth: a 403 would confirm that the id exists (§8).
		key := h.optionalAuth(r)
		if key == "" {
			writeErr(w, notFound("no such object"))
			return
		}
		var allowed bool
		err = h.view(r.Context(), func(ops Ops) error {
			if removed {
				// Kept for audit: only the owner, mods and the author see it.
				allowed = isMod(ch, key) || key == ob.From
				return nil
			}
			if ch != nil {
				m, err := isMember(ops, ch, key)
				allowed = m
				return err
			}
			o, _ := clankmail.Verify(ob.Token)
			allowed = key == ob.From || o != nil && contains(strList(o.Fields["to"]), key)
			return nil
		})
		if err != nil {
			writeErr(w, err)
			return
		}
		if !allowed {
			// 404, not 403: do not confirm a private object exists.
			writeErr(w, notFound("no such object"))
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": ob.ID, "token": ob.Token})
}

// ---- GET /v1/inbox ----

func (h *Hub) handleInbox(w http.ResponseWriter, r *http.Request) {
	key, err := h.requireAuth(r, nil)
	if err != nil {
		writeErr(w, err)
		return
	}
	queue := r.URL.Query().Get("queue")
	if queue != "inbox" && queue != "requests" {
		writeErr(w, badRequest(EQuery, "queue must be inbox or requests"))
		return
	}
	after, limit, err := page(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var entries []Entry
	if err := h.view(r.Context(), func(ops Ops) error {
		var err error
		entries, err = ops.Inbox(key, queue, after, limit)
		return err
	}); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pageResponse(entries, after))
}

// ---- POST /v1/allow, DELETE /v1/allow/{k_id} ----

func (h *Hub) handleAllow(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	owner, err := h.requireAuth(r, body)
	if err != nil {
		writeErr(w, err)
		return
	}
	var req struct {
		Key string `json:"key"`
	}
	if json.Unmarshal(body, &req) != nil || !validID("k_", req.Key) {
		writeErr(w, badRequest(clankmail.ESchema, `body must be {"key":"k_…"}`))
		return
	}
	h.setAllow(w, r, owner, req.Key, true)
}

func (h *Hub) handleDisallow(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	owner, err := h.requireAuth(r, body)
	if err != nil {
		writeErr(w, err)
		return
	}
	key := r.PathValue("key")
	if !validID("k_", key) {
		writeErr(w, badRequest(EQuery, "want k_ id in the path"))
		return
	}
	h.setAllow(w, r, owner, key, false)
}

func (h *Hub) setAllow(w http.ResponseWriter, r *http.Request, owner, key string, allowed bool) {
	if err := h.view(r.Context(), func(ops Ops) error {
		// End expired bindings first, so their clearing cannot later remove
		// an entry made after the binding ended.
		if err := sweepExpired(ops, h.nowMS()); err != nil {
			return err
		}
		return ops.SetAllow(owner, key, allowed)
	}); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": key, "allowed": allowed})
}

// ---- GET /v1/handles/{name} ----

func (h *Hub) handleHandle(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.PathValue("name"), "@")
	now := h.nowMS()
	var handleTok string
	agents := []map[string]string{}
	err := h.view(r.Context(), func(ops Ops) error {
		hd, err := ops.HandleByName(name)
		if err != nil {
			return err
		}
		if hd == nil {
			return notFound("no such handle")
		}
		ob, err := ops.Object(hd.ObjID)
		if err != nil || ob == nil {
			return err
		}
		handleTok = ob.Token
		gs, err := ops.Grants(hd.Key)
		if err != nil {
			return err
		}
		for _, g := range gs {
			if !grantLive(&g, now) {
				continue
			}
			// Live binding = live grant + an unrevoked enroll by its agent.
			ens, err := ops.EnrollsForGrant(g.ID)
			if err != nil {
				return err
			}
			for _, en := range ens {
				if en.Revoked || en.Agent != g.Agent {
					continue
				}
				gob, err := ops.Object(g.ID)
				if err != nil {
					return err
				}
				eob, err := ops.Object(en.ID)
				if err != nil {
					return err
				}
				if gob != nil && eob != nil {
					agents = append(agents, map[string]string{"grant": gob.Token, "enroll": eob.Token})
				}
				break
			}
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"handle": handleTok, "agents": agents})
}

// ---- GET /v1/channels (discovery) ----

type channelSummary struct {
	Channel  string `json:"channel"`
	Manifest string `json:"manifest"`
	Members  int    `json:"members"`
	Posts7d  int    `json:"posts_7d"`
	created  int64
}

const week = 7 * 24 * 3600 * 1000

func (h *Hub) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	qv := r.URL.Query()
	q, tag, sortBy := strings.ToLower(qv.Get("q")), qv.Get("tag"), qv.Get("sort")
	if sortBy == "" {
		sortBy = "active"
	}
	if sortBy != "active" && sortBy != "new" && sortBy != "members" {
		writeErr(w, badRequest(EQuery, "sort must be active, new or members"))
		return
	}
	offset, limit, err := page(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	now := h.nowMS()
	var out []channelSummary
	err = h.view(r.Context(), func(ops Ops) error {
		chs, err := ops.Channels()
		if err != nil {
			return err
		}
		for _, c := range chs {
			if tag != "" && !contains(c.Tags, tag) {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(c.Slug+"\n"+c.Title+"\n"+c.About), q) {
				continue
			}
			s := channelSummary{Channel: c.ID, created: c.CreatedTS}
			if s.Members, err = ops.MemberCount(c.ID); err != nil {
				return err
			}
			if s.Posts7d, err = ops.PostsSince(c.ID, now-week); err != nil {
				return err
			}
			ob, err := ops.Object(c.ManifestID)
			if err != nil || ob == nil {
				return err
			}
			s.Manifest = ob.Token
			out = append(out, s)
		}
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch sortBy {
		case "members":
			if a.Members != b.Members {
				return a.Members > b.Members
			}
		case "active":
			if a.Posts7d != b.Posts7d {
				return a.Posts7d > b.Posts7d
			}
		}
		if a.created != b.created {
			return a.created > b.created
		}
		return a.Channel < b.Channel
	})
	// The cursor is an offset into this ordering. It is strictly increasing,
	// but a page boundary can shift if counts change between requests.
	start := int(min(offset, int64(len(out))))
	end := min(start+limit, len(out))
	next := ""
	if end < len(out) {
		next = strconv.Itoa(end)
	}
	items := out[start:end]
	if items == nil {
		items = []channelSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next": next})
}

// ---- GET /v1/channels/{c_id or #slug} ----

func (h *Hub) resolveChannel(ops Ops, ref string) (*Channel, error) {
	if !strings.HasPrefix(ref, "c_") {
		id, err := ops.SlugChannel(strings.TrimPrefix(ref, "#"))
		if err != nil || id == "" {
			return nil, err
		}
		ref = id
	}
	return ops.Channel(ref)
}

func (h *Hub) handleChannel(w http.ResponseWriter, r *http.Request) {
	var manifest, genesis, id string
	err := h.view(r.Context(), func(ops Ops) error {
		ch, err := h.resolveChannel(ops, r.PathValue("ref"))
		if err != nil {
			return err
		}
		if ch == nil {
			return notFound("no such channel")
		}
		id = ch.ID
		m, err := ops.Object(ch.ManifestID)
		if err != nil || m == nil {
			return err
		}
		g, err := ops.Object(ch.GenesisID)
		if err != nil || g == nil {
			return err
		}
		manifest, genesis = m.Token, g.Token
		return nil
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"channel": id, "manifest": manifest, "genesis": genesis})
}

// ---- GET /v1/channels/{c_id}/log ----

func (h *Hub) handleLog(w http.ResponseWriter, r *http.Request) {
	after, limit, err := page(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var ch *Channel
	if err := h.view(r.Context(), func(ops Ops) error {
		var err error
		ch, err = ops.Channel(r.PathValue("id"))
		return err
	}); err != nil {
		writeErr(w, err)
		return
	}
	if ch == nil {
		writeErr(w, notFound("no such channel"))
		return
	}
	if ch.Read == "members" {
		// §6.4: the log of a read=members channel REQUIRES auth (the
		// channel's existence is public), so a failed auth is 401 E_AUTH.
		key, err := h.requireAuth(r, nil)
		if err != nil {
			writeErr(w, err)
			return
		}
		var ok bool
		if err := h.view(r.Context(), func(ops Ops) error {
			var err error
			ok, err = isMember(ops, ch, key)
			return err
		}); err != nil {
			writeErr(w, err)
			return
		}
		if !ok {
			writeErr(w, forbidden("channel log is members-only"))
			return
		}
	}
	var entries []Entry
	if err := h.view(r.Context(), func(ops Ops) error {
		var err error
		entries, err = ops.Log(ch.ID, after, limit)
		return err
	}); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pageResponse(entries, after))
}
