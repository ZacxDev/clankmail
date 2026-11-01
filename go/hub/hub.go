// Package hub is a minimal ClankMail hub (SPEC.md §5, §8): it accepts signed
// tokens on POST /v1/submit, enforces acceptance and per-type authorisation,
// stores them, and serves inboxes, handles, channels and discovery.
//
// Authenticity always comes from clankmail.Verify; this package never
// re-implements token verification.
package hub

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ZacxDev/clankmail/go/clankmail"
)

// Hub error codes beyond the §4 pipeline codes.
const (
	EStale     = "E_STALE"
	ERevoked   = "E_REVOKED"
	EForbidden = "E_FORBIDDEN"
	EAuth      = "E_AUTH"  // 401: missing/invalid/stale/replayed auth where auth is required
	EQuery     = "E_QUERY" // 400: bad query parameter or cursor
	ERate      = "E_RATE"
	ENotFound  = "E_NOT_FOUND"
	EInternal  = "E_INTERNAL"
)

const (
	submitWindowMS = 300_000 // §5
	// enrollCooldownMS is §6.3 rule 2: after an agent revokes its own
	// enroll, the hub refuses a new enroll from that key for 24 h of hub
	// time, so the owner's kill switch still reaches a key that withdrew.
	enrollCooldownMS = 86_400_000
	authWindowMS     = 60_000 // §6.4
	maxPageLimit     = 200    // §8
	defaultLimit     = 50
)

// Config configures a Hub.
type Config struct {
	Name     string           // this hub's DNS name (§2), e.g. "hub.example"
	Store    Store            // required
	Now      func() time.Time // injectable clock; defaults to time.Now
	KeyLimit Limit            // per signer key on submit; zero value = DefaultKeyLimit
	IPLimit  Limit            // per client address on submit; zero value = DefaultIPLimit
	// TrustedProxies are the front proxies whose X-Forwarded-For (or
	// ClientIPHeader, when set) is believed (§5). Empty: the TCP peer is the
	// client.
	TrustedProxies []netip.Prefix
	// ClientIPHeader, when set, names a header (e.g. CF-Connecting-IP) that
	// a trusted proxy fills with the single client address, for fronts that
	// overwrite X-Forwarded-For. It then REPLACES X-Forwarded-For as the
	// only source of the client address: XFF is not consulted at all. The
	// header is believed only from a peer inside TrustedProxies, and only
	// when it holds exactly one IP address; otherwise the peer is the
	// client. Requires a non-empty TrustedProxies.
	//
	// The hub checks only its IMMEDIATE peer. The header is therefore only as
	// trustworthy as the path in front: every hop must overwrite or strip a
	// client-supplied value, and the origin must accept traffic only from the
	// front that sets it (for a CDN, an origin lock such as authenticated
	// origin pulls). Otherwise a client rotating the header gets a fresh
	// per-address bucket per request.
	ClientIPHeader string
}

// Hub is an http.Handler serving the §8 API.
type Hub struct {
	cfg Config
	// rejected remembers, for the freshness window, every token id that was
	// charged to its signer's key and then refused, with the refusal. A
	// repeat gets the same answer without a second charge, so each token
	// costs its signer at most once however often a third party replays it.
	// Guarded by mu. In memory only: a restart forgets it, which is safe
	// (it can only cost each token one more charge).
	rejected  map[string]rejection
	nextPrune int64
	mux       *http.ServeMux
	mu        sync.Mutex // serialises submissions: check-then-apply must not interleave
	keyRL     *limiter
	ipRL      *limiter
}

// New returns a Hub. Rate limits are always on: a zero Limit means the default.
func New(cfg Config) (*Hub, error) {
	if cfg.Store == nil {
		return nil, errors.New("hub: Store is required")
	}
	if err := checkHubName(cfg.Name); err != nil {
		return nil, err
	}
	if cfg.ClientIPHeader != "" && !isToken(cfg.ClientIPHeader) {
		// A name with a space, colon or other non-token byte can never match a
		// received header, so it would silently do nothing (every visitor in
		// the proxy's one bucket).
		return nil, fmt.Errorf("hub: ClientIPHeader %q is not a valid header name", cfg.ClientIPHeader)
	}
	if cfg.ClientIPHeader != "" && len(cfg.TrustedProxies) == 0 {
		// The header would be ignored from every peer: a setting that
		// silently does nothing.
		return nil, errors.New("hub: ClientIPHeader requires TrustedProxies")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.KeyLimit == (Limit{}) {
		cfg.KeyLimit = DefaultKeyLimit
	}
	if cfg.IPLimit == (Limit{}) {
		cfg.IPLimit = DefaultIPLimit
	}
	h := &Hub{cfg: cfg, mux: http.NewServeMux(), keyRL: newLimiter(cfg.KeyLimit), ipRL: newLimiter(cfg.IPLimit)}
	h.mux.HandleFunc("POST /v1/submit", h.handleSubmit)
	h.mux.HandleFunc("GET /v1/objects/{id}", h.handleObject)
	h.mux.HandleFunc("GET /v1/inbox", h.handleInbox)
	h.mux.HandleFunc("POST /v1/allow", h.handleAllow)
	h.mux.HandleFunc("DELETE /v1/allow/{key}", h.handleDisallow)
	h.mux.HandleFunc("GET /v1/handles/{name}", h.handleHandle)
	h.mux.HandleFunc("GET /v1/channels", h.handleDiscovery)
	h.mux.HandleFunc("GET /v1/channels/{ref}", h.handleChannel)
	h.mux.HandleFunc("GET /v1/channels/{id}/log", h.handleLog)
	h.mux.HandleFunc("GET /v1/subs", h.handleSubs)
	h.mux.HandleFunc("GET /v1/digest", h.handleDigest)
	h.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, &hubErr{http.StatusNotFound, ENotFound, "no such endpoint"})
	})
	return h, nil
}

// checkHubName is a coarse §2 check on the configured name. It catches the
// mistakes an operator makes (port, trailing dot, uppercase); it is not the
// full per-label validation the reference schema applies to tokens.
func checkHubName(name string) error {
	if name == "" || strings.HasSuffix(name, ".") || strings.Contains(name, ":") ||
		len(name) > 253 || !strings.Contains(name, ".") || strings.ToLower(name) != name {
		return errors.New("hub: Name must be a lowercase DNS name with a dot, no port")
	}
	return nil
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }

func (h *Hub) nowMS() int64 { return h.cfg.Now().UnixMilli() }

// hubErr is an API error: {"error": code, "detail": detail} with status.
type hubErr struct {
	status       int
	code, detail string
}

func (e *hubErr) Error() string { return e.code + ": " + e.detail }

func forbidden(detail string) *hubErr { return &hubErr{http.StatusForbidden, EForbidden, detail} }
func notFound(detail string) *hubErr  { return &hubErr{http.StatusNotFound, ENotFound, detail} }
func badRequest(code, detail string) *hubErr {
	return &hubErr{http.StatusBadRequest, code, detail}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var he *hubErr
	if !errors.As(err, &he) {
		he = &hubErr{http.StatusInternalServerError, EInternal, "internal error"}
	}
	writeJSON(w, he.status, map[string]string{"error": he.code, "detail": he.detail})
}

// verify runs the §4 pipeline and maps a failure to a 400 with its code.
func verify(token string) (*clankmail.Object, *hubErr) {
	obj, err := clankmail.Verify(token)
	if err != nil {
		var ce *clankmail.Error
		if errors.As(err, &ce) {
			return nil, badRequest(ce.Code, ce.Detail)
		}
		return nil, badRequest(clankmail.EFormat, err.Error())
	}
	return obj, nil
}

func absDiff(a, b int64) int64 {
	if a > b {
		return a - b
	}
	return b - a
}

// clientAddr is the rate-limit key for a request's client (§5). The TCP peer
// is the client unless it is a trusted proxy; then X-Forwarded-For is walked
// right to left, skipping trusted proxies, and the first untrusted hop is
// the client (entries further left are client-supplied and spoofable). With
// ClientIPHeader set, that header replaces X-Forwarded-For (headerClient).
// IPv6 addresses are grouped by /64, since rotating within one costs nothing.
func (h *Hub) clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	ip = ip.Unmap()
	if h.cfg.ClientIPHeader != "" {
		return rateKey(h.headerClient(r, ip))
	}
	if h.trusted(ip) {
		hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				break
			}
			ip = hop.Unmap()
			if !h.trusted(ip) {
				break
			}
		}
	}
	return rateKey(ip)
}

// headerClient is the client address under ClientIPHeader. Fail-closed: the
// header counts only from a trusted peer and only when it is exactly one IP
// address (one header line, no list, no zone); anything else — absent,
// empty, a list, garbage — leaves the peer as the client. Falling back to the
// peer, never to X-Forwarded-For or the raw string, means a malformed header
// cannot mint a fresh rate-limit bucket per request.
func (h *Hub) headerClient(r *http.Request, peer netip.Addr) netip.Addr {
	if !h.trusted(peer) {
		return peer
	}
	v := r.Header.Values(h.cfg.ClientIPHeader)
	if len(v) != 1 {
		return peer
	}
	c, err := netip.ParseAddr(strings.TrimSpace(v[0]))
	if err != nil || c.Zone() != "" {
		return peer
	}
	return c.Unmap()
}

// rateKey is the per-address rate-limit key for ip: IPv6 grouped by /64.
func rateKey(ip netip.Addr) string {
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}

func (h *Hub) trusted(ip netip.Addr) bool {
	for _, p := range h.cfg.TrustedProxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ---- POST /v1/submit (§5) ----

func (h *Hub) handleSubmit(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, clankmail.MaxToken+3))
	if err != nil {
		writeErr(w, badRequest(clankmail.EFormat, "could not read body"))
		return
	}
	// §5: the per-client-address limit is charged before anything else, even
	// signature verification, so malformed and rejected submissions cost
	// budget too.
	if !h.ipRL.allow(h.nowMS(), h.clientAddr(r)) {
		writeErr(w, &hubErr{http.StatusTooManyRequests, ERate, "rate limit exceeded (client address)"})
		return
	}
	// Surrounding whitespace (a trailing newline from a shell) is not part of
	// the token; the signature covers the payload, not the transport.
	id, herr := h.submit(r.Context(), strings.TrimSpace(string(raw)))
	if herr != nil {
		writeErr(w, herr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

// rejection is a remembered refusal of a charged token.
type rejection struct {
	err *hubErr
	ts  int64 // the token's ts; once outside the window it is stale anyway
}

func (h *Hub) submit(ctx context.Context, token string) (string, error) {
	obj, herr := verify(token)
	if herr != nil {
		return "", herr
	}
	// Stateless refusal first, so it never reaches the key charge.
	if obj.Type == "auth" {
		return "", forbidden("auth tokens are never submitted (§6.4)")
	}
	now := h.nowMS()

	h.mu.Lock()
	defer h.mu.Unlock()
	if now >= h.nextPrune {
		for id, rj := range h.rejected {
			if rj.ts < now-submitWindowMS {
				delete(h.rejected, id)
			}
		}
		h.nextPrune = now + 10_000
	}
	charged := false
	err := h.cfg.Store.Tx(ctx, func(ops Ops) error {
		// Order matters (§5). A stored id is answered first, so a late retry
		// of an accepted object still gets its original result; then
		// freshness. Neither charges the signer's key: anyone can replay a
		// victim's public or stale tokens, and charging the victim for that
		// would let a stranger drain its budget (and block its revoke). The
		// replayer's own client address has already paid in handleSubmit.
		if prev, err := ops.Object(obj.ID); err != nil || prev != nil {
			return err
		}
		if absDiff(obj.Fields["ts"].(int64), now) > submitWindowMS {
			return badRequest(EStale, "ts outside ±300 s of hub time")
		}
		// A fresh token may still be a replay: anyone holding it (another
		// hub's operator, a reader of a channel) can resend it within the
		// window. What is true here is that this id has not been charged
		// before: stored ids returned above, and charged-then-refused ids
		// are answered from memory. So the key is charged once per token,
		// and forbidden fresh submissions still pay that once.
		if rj, ok := h.rejected[obj.ID]; ok {
			return rj.err
		}
		if !h.keyRL.allow(now, obj.From) {
			return &hubErr{http.StatusTooManyRequests, ERate, "rate limit exceeded (signer key)"}
		}
		charged = true
		if err := sweepExpired(ops, now); err != nil {
			return err
		}
		if rev, err := ops.KeyRevoked(obj.From); err != nil {
			return err
		} else if rev {
			return &hubErr{http.StatusForbidden, ERevoked, "signer key is revoked"}
		}
		stored := Obj{ID: obj.ID, Type: obj.Type, From: obj.From, TS: obj.Fields["ts"].(int64), Token: token, Recv: now}
		apply, err := h.authorize(ops, obj, &stored, now)
		if err != nil {
			return err
		}
		if err := ops.PutObject(stored); err != nil {
			return err
		}
		return apply()
	})
	if err != nil {
		var he *hubErr
		if charged && errors.As(err, &he) && he.status < 500 {
			if h.rejected == nil {
				h.rejected = map[string]rejection{}
			}
			h.rejected[obj.ID] = rejection{he, obj.Fields["ts"].(int64)}
		}
		return "", err
	}
	return obj.ID, nil
}

// authorize performs the type-specific §6–§7 checks without side effects and
// returns the function that applies the object's effects once it is stored.
func (h *Hub) authorize(ops Ops, obj *clankmail.Object, stored *Obj, now int64) (func() error, error) {
	f := obj.Fields
	str := func(k string) string { s, _ := f[k].(string); return s }
	ts := f["ts"].(int64)

	switch obj.Type {
	case "handle":
		if str("hub") != h.cfg.Name {
			return nil, forbidden("handle is for hub " + str("hub"))
		}
		name := str("name")
		if owner, err := ops.HandleByName(name); err != nil {
			return nil, err
		} else if owner != nil && owner.Key != obj.From {
			return nil, forbidden("handle @" + name + " is bound to another key")
		}
		if cur, err := ops.HandleByKey(obj.From); err != nil {
			return nil, err
		} else if cur != nil && ts <= cur.TS {
			return nil, forbidden("not newer than this key's current handle")
		}
		return func() error {
			// SetHandle drops this key's old binding, releasing a renamed name.
			return ops.SetHandle(Handle{Name: name, Key: obj.From, ObjID: obj.ID, TS: ts})
		}, nil

	case "grant":
		if str("hub") != h.cfg.Name {
			return nil, forbidden("grant is for hub " + str("hub"))
		}
		grants, err := ops.Grants(obj.From)
		if err != nil {
			return nil, err
		}
		for _, g := range grants {
			if g.Name == str("name") && grantLive(&g, now) {
				return nil, forbidden("principal already has a live grant named " + g.Name)
			}
		}
		exp, _ := f["exp"].(int64)
		return func() error {
			return ops.PutGrant(Grant{ID: obj.ID, Principal: obj.From, Agent: str("agent"), Name: str("name"), Exp: exp})
		}, nil

	case "revoke":
		target, err := ops.Object(str("target"))
		if err != nil {
			return nil, err
		}
		revocable := target != nil && (target.Type == "grant" || target.Type == "handle" || target.Type == "enroll" || target.Type == "sub")
		if !revocable || target.From != obj.From {
			return nil, forbidden("target must be a grant, handle, enroll or sub signed by the same key")
		}
		return func() error {
			switch target.Type {
			case "sub":
				// §7.4: ends that subscription and nothing else.
				return ops.RevokeSub(target.ID)
			case "handle":
				cur, err := ops.HandleByKey(obj.From)
				if err != nil || cur == nil || cur.ObjID != target.ID {
					return err // that handle was already superseded
				}
				return ops.DeleteHandle(cur.Name)
			case "enroll":
				// The agent withdrawing itself ends its binding (and the
				// trust that came with it); it does not silence its key.
				ens, err := ops.EnrollsByAgent(obj.From)
				if err != nil {
					return err
				}
				for _, en := range ens {
					if en.ID == target.ID {
						if err := endBinding(ops, en, now); err != nil {
							return err
						}
					}
				}
				return ops.RevokeEnroll(target.ID)
			}
			return revokeGrant(ops, target.ID, now)
		}, nil

	case "enroll":
		g, err := ops.Grant(str("grant"))
		if err != nil {
			return nil, err
		}
		if g == nil || g.Agent != obj.From {
			return nil, forbidden("grant must exist and name the enrolling key as its agent")
		}
		if !grantLive(g, now) {
			return nil, forbidden("grant is revoked or expired")
		}
		// §6.3 rule 2: for 24 h after its last binding ended (by withdrawal
		// or expiry) a key may enroll only under the SAME principal.
		if prev, err := lastEnded(ops, obj.From); err != nil {
			return nil, err
		} else if prev != nil && now < prev.EndedAt+enrollCooldownMS {
			pg, err := ops.Grant(prev.GrantID)
			if err != nil {
				return nil, err
			}
			if pg == nil || pg.Principal != g.Principal {
				return nil, forbidden("key's binding ended less than 24 h ago; only the same principal may re-enroll it (§6.3 rule 2)")
			}
		}
		if live, err := liveEnroll(ops, obj.From, now); err != nil {
			return nil, err
		} else if live != nil {
			return nil, forbidden("key already has a live enroll on this hub")
		}
		return func() error {
			return ops.PutEnroll(Enroll{ID: obj.ID, Agent: obj.From, GrantID: g.ID})
		}, nil

	case "channel":
		return h.authorizeChannel(ops, obj, stored)

	case "join", "leave", "admit", "ban", "remove":
		return h.authorizeMembership(ops, obj, stored, now)

	case "msg":
		return h.authorizeMsg(ops, obj, stored, now)

	case "sub":
		return h.authorizeSub(ops, obj, now)
	}
	return nil, forbidden("type " + obj.Type + " is not accepted by this hub")
}

// revokeGrant applies a principal's revoke of grant gid (§6.3).
//
// Kill switch: every key whose MOST RECENT enroll names gid is refused from
// now on, even if it withdrew that enroll first. A key that has since
// enrolled under another grant has moved on and is untouched. A key that
// never enrolled on gid is untouched: naming a key in a grant gives no power
// over it. "Most recent" is arrival order at this hub.
func revokeGrant(ops Ops, gid string, now int64) error {
	if err := ops.RevokeGrant(gid); err != nil {
		return err
	}
	enrolls, err := ops.EnrollsForGrant(gid)
	if err != nil {
		return err
	}
	for _, en := range enrolls {
		if err := endBinding(ops, en, now); err != nil {
			return err
		}
		mine, err := ops.EnrollsByAgent(en.Agent)
		if err != nil {
			return err
		}
		if len(mine) > 0 && mine[len(mine)-1].GrantID == gid {
			if err := ops.RevokeKey(en.Agent); err != nil {
				return err
			}
		}
	}
	return nil
}

// endBinding processes the end of a binding, once: trust does not travel, so
// the key leaves every allow list (§6.3 rule 3).
func endBinding(ops Ops, en Enroll, at int64) error {
	if en.Ended {
		return nil
	}
	if err := ops.EndBinding(en.ID, at); err != nil {
		return err
	}
	return ops.ClearAllowFor(en.Agent)
}

// sweepExpired ends bindings whose grant has expired. It runs before any
// allow-list read or write, so an expiry takes effect as if it were eager.
func sweepExpired(ops Ops, now int64) error {
	ens, err := ops.ExpiredBindings(now)
	if err != nil {
		return err
	}
	for _, en := range ens {
		g, err := ops.Grant(en.GrantID)
		if err != nil || g == nil {
			return err
		}
		// An expiry ends the binding at the grant's exp instant, not when
		// the hub happens to notice.
		if err := endBinding(ops, en, g.Exp); err != nil {
			return err
		}
	}
	return nil
}

// lastEnded returns key's binding that ended most recently, or nil.
func lastEnded(ops Ops, key string) (*Enroll, error) {
	ens, err := ops.EnrollsByAgent(key)
	var last *Enroll
	for i := range ens {
		if ens[i].Ended && (last == nil || ens[i].EndedAt >= last.EndedAt) {
			last = &ens[i]
		}
	}
	return last, err
}

func grantLive(g *Grant, now int64) bool { return !g.Revoked && (g.Exp == 0 || g.Exp > now) }

// liveEnroll returns key's live enroll: unrevoked, on a live grant.
func liveEnroll(ops Ops, key string, now int64) (*Enroll, error) {
	ens, err := ops.EnrollsByAgent(key)
	if err != nil {
		return nil, err
	}
	for _, en := range ens {
		if en.Revoked {
			continue
		}
		g, err := ops.Grant(en.GrantID)
		if err != nil {
			return nil, err
		}
		if g != nil && grantLive(g, now) {
			return &en, nil
		}
	}
	return nil, nil
}

func strList(v any) []string {
	a, _ := v.([]any)
	out := make([]string, 0, len(a))
	for _, x := range a {
		out = append(out, x.(string))
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func (h *Hub) authorizeChannel(ops Ops, obj *clankmail.Object, stored *Obj) (func() error, error) {
	f := obj.Fields
	str := func(k string) string { s, _ := f[k].(string); return s }
	ts := f["ts"].(int64)
	next := Channel{
		Slug: str("slug"), Title: str("title"), About: str("about"), Tags: strList(f["tags"]),
		Read: str("read"), Post: str("post"), Join: str("join"), Mods: strList(f["mods"]),
		ManifestID: obj.ID, ManifestTS: ts,
	}
	// §7.1: slugs are unique per hub. A slug bound to a different channel is
	// refused, so a channel is never accepted under a name it cannot be
	// reached by.
	slugFree := func(id string) error {
		c, err := ops.SlugChannel(next.Slug)
		if err != nil {
			return err
		}
		if c != "" && c != id {
			return forbidden("slug #" + next.Slug + " is bound to another channel")
		}
		return nil
	}

	if _, update := f["channel"]; !update {
		next.ID = clankmail.ChannelID(obj.Payload)
		next.Owner, next.GenesisID, next.CreatedTS = obj.From, obj.ID, ts
		stored.Channel = next.ID
		if err := slugFree(next.ID); err != nil {
			return nil, err
		}
		return func() error {
			if err := ops.PutChannel(next); err != nil {
				return err
			}
			if err := ops.SetMembership(next.ID, next.Owner, "member"); err != nil {
				return err
			}
			return ops.BindSlug(next.Slug, next.ID)
		}, nil
	}

	cur, err := ops.Channel(str("channel"))
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, notFound("unknown channel")
	}
	if obj.From != cur.Owner {
		return nil, forbidden("only the channel owner may update it")
	}
	if ts <= cur.ManifestTS {
		return nil, forbidden("update ts is not newer than the current manifest")
	}
	if err := slugFree(cur.ID); err != nil {
		return nil, err
	}
	next.ID, next.Owner, next.GenesisID, next.CreatedTS = cur.ID, cur.Owner, cur.GenesisID, cur.CreatedTS
	stored.Channel = cur.ID
	return func() error {
		if err := ops.PutChannel(next); err != nil {
			return err
		}
		if next.Slug == cur.Slug {
			return nil
		}
		// A changed slug releases the old one.
		if err := ops.UnbindSlug(cur.Slug); err != nil {
			return err
		}
		return ops.BindSlug(next.Slug, cur.ID)
	}, nil
}

// standing is a key's authority in one channel.
type standing struct{ banned, mod, member bool }

// standingOf is the single place channel authority is decided. A live ban
// overrides the mods list and membership (§7.3): a banned key is neither a
// mod nor a member, whatever the manifest says. The owner cannot be banned.
func standingOf(ops Ops, ch *Channel, key string, now int64) (standing, error) {
	if key == ch.Owner {
		return standing{mod: true, member: true}, nil
	}
	b, err := banned(ops, ch, key, now)
	if err != nil {
		return standing{}, err
	}
	if b {
		return standing{banned: true}, nil
	}
	mod := contains(ch.Mods, key)
	st, err := ops.Membership(ch.ID, key)
	return standing{mod: mod, member: mod || st == "member"}, err
}

func banned(ops Ops, ch *Channel, key string, now int64) (bool, error) {
	until, _, ok, err := ops.BanUntil(ch.ID, key)
	if err != nil || !ok {
		return false, err
	}
	return banLive(until, now), nil
}

// banLive is the single definition of a live ban (§7.3): until 0 = forever.
func banLive(until, now int64) bool { return until == 0 || until > now }

// mayRead reports whether key may read ch's log (§8): anyone for read=public,
// an unbanned member for read=members. Subscriptions and the digest use it.
func mayRead(ops Ops, ch *Channel, key string, now int64) (bool, error) {
	if ch.Read == "public" {
		return true, nil
	}
	s, err := standingOf(ops, ch, key, now)
	return s.member, err
}

func (h *Hub) authorizeMembership(ops Ops, obj *clankmail.Object, stored *Obj, now int64) (func() error, error) {
	f := obj.Fields
	str := func(k string) string { s, _ := f[k].(string); return s }
	ch, err := ops.Channel(str("channel"))
	if err != nil {
		return nil, err
	}
	if ch == nil {
		return nil, notFound("unknown channel")
	}
	stored.Channel = ch.ID
	set := func(key, state string) func() error {
		return func() error { return ops.SetMembership(ch.ID, key, state) }
	}

	switch obj.Type {
	case "join":
		if b, err := banned(ops, ch, obj.From, now); err != nil {
			return nil, err
		} else if b {
			return nil, forbidden("banned from this channel")
		}
		st, err := ops.Membership(ch.ID, obj.From)
		if err != nil {
			return nil, err
		}
		if st == "member" {
			return func() error { return nil }, nil
		}
		if ch.Join == "open" {
			return set(obj.From, "member"), nil
		}
		return set(obj.From, "pending"), nil

	case "leave":
		return set(obj.From, ""), nil

	case "admit":
		if s, err := standingOf(ops, ch, obj.From, now); err != nil {
			return nil, err
		} else if !s.mod {
			return nil, forbidden("only the owner or a mod may admit")
		}
		st, err := ops.Membership(ch.ID, str("member"))
		if err != nil {
			return nil, err
		}
		if st != "pending" {
			return nil, forbidden("member has no pending join")
		}
		return set(str("member"), "member"), nil

	case "ban":
		m := str("member")
		if s, err := standingOf(ops, ch, obj.From, now); err != nil {
			return nil, err
		} else if !s.mod {
			return nil, forbidden("only the owner or a mod may ban")
		}
		if m == ch.Owner || (contains(ch.Mods, m) && obj.From != ch.Owner) {
			return nil, forbidden("only the owner may ban a mod, and the owner cannot be banned")
		}
		until, hasUntil := f["until"].(int64)
		passed := hasUntil && until <= now
		rank := 1
		if obj.From == ch.Owner {
			rank = 2
		}
		curUntil, curRank, has, err := ops.BanUntil(ch.ID, m)
		if err != nil {
			return nil, err
		}
		if has && (curUntil == 0 || curUntil > now) {
			// §7.3: replacing a live ban needs a signer ranked at least as
			// high as its signer (owner > mods).
			if rank < curRank {
				return nil, forbidden("a mod cannot change the owner's ban")
			}
			if passed {
				return func() error { return ops.LiftBan(ch.ID, m) }, nil // unban
			}
			return func() error { return ops.SetBan(ch.ID, m, until, rank) }, nil
		}
		if passed {
			return nil, forbidden("ban until has passed and the key is not banned")
		}
		return func() error {
			if err := ops.SetMembership(ch.ID, m, ""); err != nil {
				return err
			}
			return ops.SetBan(ch.ID, m, until, rank)
		}, nil

	case "remove":
		author, _, ok, err := ops.LogEntry(ch.ID, str("target"))
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, forbidden("target is not a post in this channel")
		}
		s, err := standingOf(ops, ch, obj.From, now)
		if err != nil {
			return nil, err
		}
		if s.banned || (obj.From != author && !s.mod) {
			return nil, forbidden("only the owner, a mod or the author may remove a post")
		}
		return func() error { return ops.HideLog(ch.ID, str("target")) }, nil
	}
	return nil, forbidden("unsupported membership type")
}

func (h *Hub) authorizeMsg(ops Ops, obj *clankmail.Object, stored *Obj, now int64) (func() error, error) {
	to := strList(obj.Fields["to"])
	if strings.HasPrefix(to[0], "c_") {
		ch, err := ops.Channel(to[0])
		if err != nil {
			return nil, err
		}
		if ch == nil {
			return nil, notFound("unknown channel")
		}
		stored.Channel = ch.ID
		if err := canPost(ops, ch, obj.From, now); err != nil {
			return nil, err
		}
		re, _ := obj.Fields["re"].(string)
		return func() error { return ops.AppendLog(ch.ID, obj.ID, re, now) }, nil
	}

	// Direct delivery (§7.2): one stored token, one inbox entry per recipient.
	thread, err := threadRoot(ops, obj)
	if err != nil {
		return nil, err
	}
	queues := make([]string, len(to))
	for i, r := range to {
		q, err := queueFor(ops, obj, r)
		if err != nil {
			return nil, err
		}
		queues[i] = q
	}
	return func() error {
		for i, r := range to {
			if err := ops.AddInbox(r, queues[i], obj.ID, thread); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

// maxThreadDepth bounds the re walk. Ids are content hashes so a cycle is
// impossible, but a long chain still costs one lookup per hop.
const maxThreadDepth = 256

// threadRoot derives a message's thread root (§7.2) by following re to a
// stored message with no re. It is "" when the chain leaves this hub's store
// or exceeds maxThreadDepth: an unsigned convenience must not guess.
func threadRoot(ops Ops, obj *clankmail.Object) (string, error) {
	cur, fields := obj.ID, obj.Fields
	for i := 0; i < maxThreadDepth; i++ {
		re, _ := fields["re"].(string)
		if re == "" {
			return cur, nil
		}
		parent, err := ops.Object(re)
		if err != nil || parent == nil || parent.Type != "msg" {
			return "", err
		}
		cur, fields = parent.ID, map[string]any{"re": storedFields(parent.Token).Re}
	}
	return "", nil
}

// stored is the part of an accepted msg payload the hub re-reads.
type stored struct {
	Re string
	To []string
}

// storedFields re-reads a token this hub verified when it accepted it. It
// does NOT verify the signature again: that work was done once, at
// acceptance, and repeating it per lookup (up to maxThreadDepth per reply,
// under the submit lock) is pure cost. Never call it on an incoming token.
func storedFields(token string) stored {
	var m stored
	parts := strings.Split(token, ".")
	if len(parts) != 4 {
		return m
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return m
	}
	// Decode into a map and read the EXACT keys "re" and "to". A struct
	// decode would match keys case-insensitively, so a payload carrying
	// both "to" and "TO" (an unknown field §3.2 tells verifiers to ignore)
	// would be read by the hub as TO while every verifier reads to.
	var f map[string]any
	if json.Unmarshal(b, &f) != nil {
		return m
	}
	m.Re, _ = f["re"].(string)
	m.To = strList(f["to"])
	return m
}

// canPost enforces a channel's post policy (§7.1, §7.2) against key.
func canPost(ops Ops, ch *Channel, key string, now int64) error {
	if b, err := banned(ops, ch, key, now); err != nil {
		return err
	} else if b {
		return forbidden("banned from this channel")
	}
	s, err := standingOf(ops, ch, key, now)
	if err != nil {
		return err
	}
	var ok bool
	switch ch.Post {
	case "anyone":
		ok = true
	case "members":
		ok = s.member
	case "mods":
		ok = s.mod
	case "owner":
		ok = key == ch.Owner
	}
	if !ok {
		return forbidden("post policy is " + ch.Post)
	}
	return nil
}

// queueFor decides a direct message's queue for one recipient (§7.2).
//
// "inbox" if the sender is on the recipient's allow list, or the message
// replies (re) to a message the recipient sent whose `to` includes this
// sender. That last condition is stricter than the spec text: without it
// anyone could cite a recipient's public channel post (whose `to` is a c_ id)
// and skip "requests".
func queueFor(ops Ops, obj *clankmail.Object, recipient string) (string, error) {
	if ok, err := ops.Allowed(recipient, obj.From); err != nil || ok {
		return "inbox", err
	}
	re, _ := obj.Fields["re"].(string)
	if re == "" {
		return "requests", nil
	}
	orig, err := ops.Object(re)
	if err != nil {
		return "", err
	}
	if orig == nil || orig.Type != "msg" || orig.From != recipient {
		return "requests", nil
	}
	// §6.3 rule 3: a key loses the reply route for every message that
	// arrived before its last binding ended. A never-bound key has no end.
	if prev, err := lastEnded(ops, obj.From); err != nil {
		return "", err
	} else if prev != nil && orig.Recv <= prev.EndedAt {
		return "requests", nil
	}
	if contains(storedFields(orig.Token).To, obj.From) {
		return "inbox", nil
	}
	return "requests", nil
}

// isToken reports whether s is a non-empty HTTP field name (RFC 9110 §5.6.2 tchar).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}
