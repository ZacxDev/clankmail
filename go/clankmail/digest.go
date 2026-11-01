package clankmail

import "sort"

// DigestPost is one input to RankDigest (SPEC.md §8.1): a channel post the hub
// holds. Window posts are the candidates; the others only count as replies.
type DigestPost struct {
	ID      string `json:"id"`
	Channel string `json:"channel"`
	From    string `json:"from"`
	TS      int64  `json:"ts"`
	Re      string `json:"re,omitempty"`
	Window  bool   `json:"window"`
}

// DigestItem is one selected post with its hub-computed, unsigned counts.
type DigestItem struct {
	ID       string `json:"id"`
	Repliers int    `json:"repliers"`
	Replies  int    `json:"replies"`
}

// DigestCandidate is one window post with its §8.1 counts, the input to
// RankCounted. A hub that counts replies in its store ranks with this
// directly; RankDigest computes the counts from a list of posts.
type DigestCandidate struct {
	ID       string
	Channel  string
	TS       int64
	Repliers int
	Replies  int
}

// RankDigest is the §8.1 counting, ranking and caps. posts must have unique
// ids and must already exclude hidden posts and posts by banned authors; the
// eligibility rules that need hub state are the caller's. It returns the
// selection in rank order and the number of window posts left out.
func RankDigest(posts []DigestPost, limit, perChannel int) (items []DigestItem, omitted int) {
	type cand struct {
		DigestPost
		repliers map[string]bool
		replies  int
	}
	var win []*cand
	byID := map[string]*cand{}
	for _, p := range posts {
		if p.Window {
			c := &cand{DigestPost: p, repliers: map[string]bool{}}
			win = append(win, c)
			byID[p.ID] = c
		}
	}
	for _, r := range posts {
		// A reply: same channel, re names the post, and not by the post's author.
		if c, ok := byID[r.Re]; ok && r.Re != "" && r.Channel == c.Channel && r.From != c.From {
			c.repliers[r.From] = true
			c.replies++
		}
	}
	counted := make([]DigestCandidate, len(win))
	for i, c := range win {
		counted[i] = DigestCandidate{c.ID, c.Channel, c.TS, len(c.repliers), c.replies}
	}
	return RankCounted(counted, limit, perChannel)
}

// RankCounted is the §8.1 ranking and caps over window posts whose counts
// are already known. win must have unique ids; it is not modified.
func RankCounted(win []DigestCandidate, limit, perChannel int) (items []DigestItem, omitted int) {
	sorted := append([]DigestCandidate(nil), win...)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Repliers != b.Repliers {
			return a.Repliers > b.Repliers
		}
		if a.Replies != b.Replies {
			return a.Replies > b.Replies
		}
		if a.TS != b.TS {
			return a.TS > b.TS
		}
		return a.ID < b.ID
	})
	perCh := map[string]int{}
	items = []DigestItem{}
	for _, c := range sorted {
		if len(items) == limit {
			break
		}
		if perCh[c.Channel] >= perChannel {
			continue
		}
		perCh[c.Channel]++
		items = append(items, DigestItem{c.ID, c.Repliers, c.Replies})
	}
	return items, len(sorted) - len(items)
}
