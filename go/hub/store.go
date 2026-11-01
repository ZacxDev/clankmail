package hub

import "context"

// Store is the hub's persistence. Every read and write goes through Tx so a
// submission's effects land atomically or not at all.
type Store interface {
	Tx(ctx context.Context, fn func(Ops) error) error
	Close() error
}

// Obj is a stored, accepted token.
type Obj struct {
	ID      string
	Type    string
	From    string
	TS      int64
	Channel string // c_ id for channel-scoped objects, "" otherwise
	Token   string
	Recv    int64 // hub arrival time, ms
}

// Grant is a stored grant (§6.2).
type Grant struct {
	ID        string
	Principal string
	Agent     string
	Name      string
	Exp       int64 // 0 = no expiry
	Revoked   bool
}

// Enroll is an agent's acceptance of one grant. A binding @handle/name is live
// only while the grant and its enroll are both live.
type Enroll struct {
	ID      string
	Agent   string
	GrantID string
	Revoked bool
	Ended   bool  // the binding's end has been processed (allow lists cleared)
	EndedAt int64 // hub ms when the binding ended (grant exp for an expiry); 0 if live
}

// Handle is a live name binding (§6.1).
type Handle struct {
	Name  string
	Key   string
	ObjID string
	TS    int64
}

// Channel is the current state of a channel (§7.1).
type Channel struct {
	ID         string
	Owner      string
	GenesisID  string
	ManifestID string
	ManifestTS int64
	CreatedTS  int64
	Slug       string
	Title      string
	About      string
	Tags       []string
	Read       string
	Post       string
	Join       string
	Mods       []string
}

// Sub is a subscription (§7.4). StartSeq is the channel-log cursor head when
// it was accepted: it covers posts with a greater cursor.
type Sub struct {
	ID       string
	Key      string
	Channel  string
	StartSeq int64
	Revoked  bool
}

// LogPost is a channel-log row with the fields the digest needs (§8.1).
type LogPost struct {
	Seq     int64
	Channel string
	ID      string
	Author  string
	Re      string
	TS      int64
	Token   string
}

// Entry is one item of a cursor-paged stream (inbox or channel log).
type Entry struct {
	Seq    int64
	Token  string
	Thread string // derived thread root (inbox only); "" when unknown
}

// Ops is the set of store operations available inside a transaction.
type Ops interface {
	PutObject(o Obj) error
	Object(id string) (*Obj, error) // nil, nil when absent

	HandleByName(name string) (*Handle, error)
	HandleByKey(key string) (*Handle, error)
	SetHandle(h Handle) error // replaces any binding of h.Key and of h.Name
	DeleteHandle(name string) error

	PutGrant(g Grant) error
	Grant(id string) (*Grant, error)
	Grants(principal string) ([]Grant, error) // unrevoked, any expiry
	RevokeGrant(id string) error

	PutEnroll(e Enroll) error
	EnrollsForGrant(grantID string) ([]Enroll, error) // including revoked ones
	EnrollsByAgent(agent string) ([]Enroll, error)    // including revoked ones
	RevokeEnroll(id string) error
	EndBinding(enrollID string, at int64) error
	ExpiredBindings(now int64) ([]Enroll, error) // not yet ended, grant exp <= now

	RevokeKey(key string) error
	KeyRevoked(key string) (bool, error)

	SetAllow(owner, key string, allowed bool) error
	Allowed(owner, key string) (bool, error)
	ClearAllowFor(key string) error // remove key from every allow list

	AddInbox(owner, queue, objID, thread string) error
	Inbox(owner, queue string, after int64, limit int) ([]Entry, error)

	PutChannel(c Channel) error // upsert by ID
	Channel(id string) (*Channel, error)
	Channels() ([]Channel, error)
	SlugChannel(slug string) (string, error) // "" when unbound
	BindSlug(slug, channel string) error
	UnbindSlug(slug string) error

	Membership(channel, key string) (string, error) // "", "member" or "pending"
	SetMembership(channel, key, state string) error // state "" removes
	MemberCount(channel string) (int, error)
	SetBan(channel, key string, until int64, rank int) error // until 0 = forever; rank of the signer
	BanUntil(channel, key string) (until int64, rank int, banned bool, err error)
	LiftBan(channel, key string) error

	AppendLog(channel, objID, re string, recv int64) error // re: the post's re, "" if none
	LogEntry(channel, objID string) (author string, hidden, ok bool, err error)
	HideLog(channel, objID string) error
	Log(channel string, after int64, limit int) ([]Entry, error) // hidden posts excluded
	PostsSince(channel string, since int64) (int, error)
	LogHead() (int64, error) // greatest channel-log cursor, 0 when empty

	Bans(channel string) (map[string]int64, error) // key -> until, every stored ban

	PutSub(s Sub) error
	LiveSub(key, channel string) (*Sub, error)
	LiveSubs(key string) ([]Sub, error) // arrival order
	RevokeSub(id string) error
	// DigestRows returns unhidden posts, in cursor order, after cursor `after`
	// from channels key has a live sub to, newer than that sub and not by key.
	DigestRows(key string, after int64, limit int) ([]LogPost, error)
	// Replies returns unhidden posts of channel whose re is one of parents.
	Replies(channel string, parents []string) ([]LogPost, error)

	// UseAuth records an auth id. It reports false if the id was already used.
	UseAuth(id string, ts int64) (bool, error)
	PruneAuth(before int64) error
}
