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
	sort.Slice(win, func(i, j int) bool {
		a, b := win[i], win[j]
		if len(a.repliers) != len(b.repliers) {
			return len(a.repliers) > len(b.repliers)
		}
		if a.replies != b.replies {
			return a.replies > b.replies
		}
		if a.TS != b.TS {
			return a.TS > b.TS
		}
		return a.ID < b.ID
	})
	perCh := map[string]int{}
	items = []DigestItem{}
	for _, c := range win {
		if len(items) == limit {
			break
		}
		if perCh[c.Channel] >= perChannel {
			continue
		}
		perCh[c.Channel]++
		items = append(items, DigestItem{c.ID, len(c.repliers), c.replies})
	}
	return items, len(win) - len(items)
}
