#!/usr/bin/env python3
"""Mutation battery for the hub's security guards (run: make hub-mutate).

Each entry breaks one guard with an exact, unique string replacement in a
scratch copy of the repo, runs the named test, and requires it to FAIL with
the expected message. Rules the harness enforces, because each one has bitten:

- Every named test is first run UNMUTATED and must pass and actually run
  ("no tests to run" counts as a failure of the control).
- A mutant that does not compile is BUILD-FAIL, never a kill. Mutants keep
  every variable used ("&& false" / "|| true") so they compile.
- A pattern that is missing or not unique is a HARNESS error.
- A red test with a different message is RED-WRONG-REASON, not a kill.
- The real source tree is checksummed before and after and must not change.
"""
import hashlib, os, shutil, subprocess, sys, tempfile

SRC = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
WORK = tempfile.mkdtemp(prefix="hub-mutate-")

H, A, S, D = "go/hub/hub.go", "go/hub/api.go", "go/hub/sqlite.go", "go/hub/digest.go"
# (guard, file, old, new, test, expected substring in failing output)
M = [
 # (guard, file, old, new, test, expected substring). Mutants keep every
 # variable used (append "&& false" / "|| true") so they COMPILE; a build
 # failure is reported as BUILD-FAIL, never as a kill.
 ("submit freshness (disabled)", H, 'if absDiff(obj.Fields["ts"].(int64), now) > submitWindowMS {', 'if absDiff(obj.Fields["ts"].(int64), now) > submitWindowMS && false {', "TestSubmitFreshness", "want 400 E_STALE, got 200"),
 ("submit freshness (window 300s->302s)", H, "submitWindowMS = 300_000", "submitWindowMS = 302_000", "TestSubmitFreshness", "want 400 E_STALE, got 200"),
 ("submit freshness (window 300s->298s)", H, "submitWindowMS = 300_000", "submitWindowMS = 298_000", "TestSubmitFreshness", "submit rejected: 400 map[detail:ts outside"),
 ("idempotency checked before freshness", H,
  '\t\tif prev, err := ops.Object(obj.ID); err != nil || prev != nil {\n\t\t\treturn err\n\t\t}\n\t\tif absDiff(obj.Fields["ts"].(int64), now) > submitWindowMS {\n\t\t\treturn badRequest(EStale, "ts outside ±300 s of hub time")\n\t\t}\n',
  '\t\tif absDiff(obj.Fields["ts"].(int64), now) > submitWindowMS {\n\t\t\treturn badRequest(EStale, "ts outside ±300 s of hub time")\n\t\t}\n\t\tif prev, err := ops.Object(obj.ID); err != nil || prev != nil {\n\t\t\treturn err\n\t\t}\n',
  "TestLateRetryIsIdempotent", "want 200, got 400"),
 ("idempotency (disabled)", H, "if prev, err := ops.Object(obj.ID); err != nil || prev != nil {", "if prev, err := ops.Object(obj.ID); err != nil || prev != nil && false {", "TestDuplicateSubmitIsIdempotent", "want 200, got 500"),
 ("auth freshness (disabled)", A, "if absDiff(ts, now) > authWindowMS {", "if absDiff(ts, now) > authWindowMS && false {", "TestAuthFreshness", "want 401 E_AUTH, got 200"),
 ("auth freshness (window 60s->62s)", H, "authWindowMS     = 60_000", "authWindowMS     = 62_000", "TestAuthFreshness", "want 401 E_AUTH, got 200"),
 ("auth replay", A, "if !fresh {", "if !fresh && false {", "TestAuthReplayRejected", "want 401 E_AUTH, got 200"),
 ("auth path binding", A, 'case f["path"] != requestPath(r):', 'case f["path"] != requestPath(r) && false:', "TestAuthBinding", "want 401 E_AUTH, got 200"),
 ("auth method binding", A, 'case f["method"] != r.Method:', 'case f["method"] != r.Method && false:', "TestAuthBinding", "want 401 E_AUTH, got 200"),
 ("auth hub binding", A, 'case f["hub"] != h.cfg.Name:', 'case f["hub"] != h.cfg.Name && false:', "TestAuthBinding", "want 401 E_AUTH, got 200"),
 ("auth body binding", A, 'case f["body"] != hex.EncodeToString(sum[:]):', 'case f["body"] != hex.EncodeToString(sum[:]) && false:', "TestAuthBinding", "want 401 E_AUTH, got 200"),
 ("auth must be t=auth", A, 'if obj.Type != "auth" {', 'if obj.Type != "auth" && false {', "TestAuthBinding", "want 401 E_AUTH, got 200"),
 ("allow list: everyone allowed", H, "if ok, err := ops.Allowed(recipient, obj.From); err != nil || ok {", "if ok, err := ops.Allowed(recipient, obj.From); err != nil || ok || true {", "TestDirectQueuePlacement", "bob requests: []"),
 ("allow list: ignored", H, "if ok, err := ops.Allowed(recipient, obj.From); err != nil || ok {", "if ok, err := ops.Allowed(recipient, obj.From); err != nil || ok && false {", "TestDirectQueuePlacement", "allowed sender not in inbox"),
 ("re rule removed", H, 'if contains(storedFields(orig.Token).To, obj.From) {', 'if contains(storedFields(orig.Token).To, obj.From) && false {', "TestDirectQueuePlacement", "reply not in scout inbox"),
 ("re rule: to-contains-sender dropped (DM)", H, 'if contains(storedFields(orig.Token).To, obj.From) {', 'if contains(storedFields(orig.Token).To, obj.From) || true {', "TestDirectQueuePlacement", "re to a message not addressed to the sender bypassed requests"),
 ("re rule: to-contains-sender dropped (channel post)", H, 'if contains(storedFields(orig.Token).To, obj.From) {', 'if contains(storedFields(orig.Token).To, obj.From) || true {', "TestReplyToChannelPostDoesNotOpenInbox", "reply to a channel post bypassed requests"),
 ("re rule: recipient-authored dropped", H, 'if orig == nil || orig.Type != "msg" || orig.From != recipient {', 'if orig == nil || orig.Type != "msg" {', "TestReplyCitingThirdPartyMessage", "bypassed requests"),
 ("thread root = parent, not root", H, '\t\tcur, fields = parent.ID, map[string]any{"re": storedFields(parent.Token).Re}\n', '\t\tcur, fields = parent.ID, map[string]any{"re": storedFields(parent.Token).Re}\n\t\treturn cur, nil\n', "TestInboxThreadRoot", "depth-2 thread"),
 ("post policy (disabled)", H, '\tif !ok {\n\t\treturn forbidden("post policy is " + ch.Post)', '\tif !ok && false {\n\t\treturn forbidden("post policy is " + ch.Post)', "TestChannelLifecycle", "want 403 E_FORBIDDEN, got 200"),
 ("post policy members => anyone", H, "\t\tok = s.member\n", "\t\tok = s.member || true\n", "TestChannelLifecycle", "want 403 E_FORBIDDEN, got 200"),
 ("pending member cannot post", H, 'return standing{mod: mod, member: mod || st == "member"}, err', 'return standing{mod: mod, member: mod || st != ""}, err', "TestMembersOnlyChannelLog", "want 403 E_FORBIDDEN, got 200"),
 ("revoked signer on submit", H, '} else if rev {\n\t\t\treturn &hubErr{http.StatusForbidden, ERevoked, "signer key is revoked"}', '} else if rev && false {\n\t\t\treturn &hubErr{http.StatusForbidden, ERevoked, "signer key is revoked"}', "TestRevokedAgentRejected", "want 403 E_REVOKED, got 200"),
 ("revoked signer on auth", A, '} else if rev {\n\t\t\treturn &hubErr{http.StatusForbidden, ERevoked, "auth signer key is revoked"}', '} else if rev && false {\n\t\t\treturn &hubErr{http.StatusForbidden, ERevoked, "auth signer key is revoked"}', "TestRevokedAgentRejected", "want 403 E_REVOKED, got 200"),
 ("grant revoke does not revoke enrolled key", H, "\t\t\tif err := ops.RevokeKey(en.Agent); err != nil {", "\t\t\tif err := ops.RevokeKey(en.Agent + \"x\"); err != nil {", "TestRevokedAgentRejected", "want 403 E_REVOKED, got 200"),
 ("grant revoke silences un-enrolled key (old rule)", H, "\tenrolls, err := ops.EnrollsForGrant(gid)\n", "\tif g, _ := ops.Grant(gid); g != nil {\n\t\tops.RevokeKey(g.Agent)\n\t}\n\tenrolls, err := ops.EnrollsForGrant(gid)\n", "TestRevokeCannotSilenceUnenrolledKey", "submit rejected: 403"),
 ("revoke: same-signer check", H, "if !revocable || target.From != obj.From {", "if !revocable {", "TestRevokedAgentRejected", "want 403 E_FORBIDDEN, got 200"),
 ("revoke: target type check", H, 'revocable := target != nil && (target.Type == "grant" || target.Type == "handle" || target.Type == "enroll" || target.Type == "sub")', 'revocable := target != nil', "TestRevokeTargetType", "want 403 E_FORBIDDEN, got 200"),
 ("enroll withdrawal revokes key", H, "\t\t\t\treturn ops.RevokeEnroll(target.ID)\n", "\t\t\t\tops.RevokeKey(target.From)\n\t\t\t\treturn ops.RevokeEnroll(target.ID)\n", "TestRevokeOwnEnroll", "submit rejected: 403"),
 ("enroll withdrawal ignored", H, "\t\t\t\treturn ops.RevokeEnroll(target.ID)\n", "\t\t\t\treturn nil\n", "TestRevokeOwnEnroll", "withdrawn binding still listed"),
 ("enroll: agent must match grant", H, "if g == nil || g.Agent != obj.From {", "if g == nil {", "TestEnrollRules", "want 403 E_FORBIDDEN, got 200"),
 ("enroll: one live per key", H, "} else if live != nil {", "} else if live != nil && false {", "TestEnrollRules", "want 403 E_FORBIDDEN, got 200"),
 ("enroll: grant must be live", H, "if !grantLive(g, now) {\n\t\t\treturn nil, forbidden", "if !grantLive(g, now) && false {\n\t\t\treturn nil, forbidden", "TestEnrollRules", "want 403 E_FORBIDDEN, got 200"),
 ("handles: grant without enroll listed", A, "\t\t\t\tif en.Revoked || en.Agent != g.Agent {", "\t\t\t\tif false && (en.Revoked || en.Agent != g.Agent) {", "TestRevokeOwnEnroll", "withdrawn binding still listed"),
 ("handles: binding needs an enroll at all", A, "\t\t\t// Live binding = live grant + an unrevoked enroll by its agent.\n", "\t\t\tif gob, _ := ops.Object(g.ID); gob != nil {\n\t\t\t\tagents = append(agents, map[string]string{\"grant\": gob.Token})\n\t\t\t\tcontinue\n\t\t\t}\n", "TestHandleGrantEnrollResolve", "un-enrolled grant listed"),
 ("handles: expired grant listed", H, "func grantLive(g *Grant, now int64) bool { return !g.Revoked && (g.Exp == 0 || g.Exp > now) }", "func grantLive(g *Grant, now int64) bool { return !g.Revoked }", "TestGrantExpiryHidesBinding", "expired binding still listed"),
 ("handle uniqueness", H, "} else if owner != nil && owner.Key != obj.From {", "} else if owner != nil && owner.Key != obj.From && false {", "TestHandleUniquenessAndHub", "want 403 E_FORBIDDEN, got 200"),
 ("handle hub field", H, 'if str("hub") != h.cfg.Name {\n\t\t\treturn nil, forbidden("handle is for hub "', 'if str("hub") != h.cfg.Name && false {\n\t\t\treturn nil, forbidden("handle is for hub "', "TestHandleUniquenessAndHub", "want 403 E_FORBIDDEN, got 200"),
 ("handle rename releases old name", S, "DELETE FROM handles WHERE key=? OR name=?", "DELETE FROM handles WHERE name=?", "TestHandleUniquenessAndHub", "submit rejected: 500"),
 ("handle: older ts cannot roll back", H, "} else if cur != nil && ts <= cur.TS {", "} else if cur != nil && ts <= cur.TS && false {", "TestHandleUniquenessAndHub", "want 403 E_FORBIDDEN, got 200"),
 ("submit rejects auth type", H, 'if obj.Type == "auth" {', 'if obj.Type == "auth" && false {', "TestSubmitRejectsAuth", "wrong reason"),
 ("rate limit", "go/hub/ratelimit.go", "if b.tokens < 1 {", "if b.tokens < 1 && false {", "TestRateLimitDefaults", "want 429 E_RATE, got 200"),
 ("remove: author-or-mod", H, "if s.banned || (obj.From != author && !s.mod) {", "if s.banned || (obj.From != author && !s.mod && false) {", "TestChannelLifecycle", "want 403 E_FORBIDDEN, got 200"),
 ("removed post hidden from log", S, "l.hidden=0 AND l.seq>?", "l.seq>?", "TestChannelLifecycle", "removed post still in log"),
 ("channel update: owner only", H, "if obj.From != cur.Owner {", "if obj.From != cur.Owner && false {", "TestChannelLifecycle", "want 403 E_FORBIDDEN, got 200"),
 ("channel update: newer ts only", H, "if ts <= cur.ManifestTS {", "if ts <= cur.ManifestTS && false {", "TestChannelLifecycle", "want 403 E_FORBIDDEN, got 200"),
 ("admit: owner/mod only", H, '\t\t} else if !s.mod {\n\t\t\treturn nil, forbidden("only the owner or a mod may admit")', '\t\t} else if !s.mod && false {\n\t\t\treturn nil, forbidden("only the owner or a mod may admit")', "TestMembersOnlyChannelLog", "want 403 E_FORBIDDEN, got 200"),
 ("ban blocks rejoin", H, '\t\t} else if b {\n\t\t\treturn nil, forbidden("banned from this channel")', '\t\t} else if b && false {\n\t\t\treturn nil, forbidden("banned from this channel")', "TestMembersOnlyChannelLog", "want 403 E_FORBIDDEN, got 200"),
 ("members-only log", A, '\t\tif !ok {\n\t\t\twriteErr(w, forbidden("channel log is members-only"))', '\t\tif !ok && false {\n\t\t\twriteErr(w, forbidden("channel log is members-only"))', "TestMembersOnlyChannelLog", "want 403 E_FORBIDDEN, got 200"),
 ("DM object visibility", A, "allowed = key == ob.From || contains(storedFields(ob.Token).To, key)", "allowed = key == ob.From || contains(storedFields(ob.Token).To, key) || true", "TestDirectObjectVisibility", "want 404 E_NOT_FOUND, got 200"),
 ("members-channel object visibility", A, "\t\t\t\t\tallowed = s.member\n", "\t\t\t\t\tallowed = s.member || true\n", "TestMembersOnlyChannelLog", "want 404 E_NOT_FOUND, got 200"),
 ("objects: DM treated as public", A, 'public := ob.Type == "channel" || ob.Channel == "" && ob.Type != "msg" ||', 'public := ob.Type == "channel" || ob.Channel == "" ||', "TestDirectObjectVisibility", "want 404 E_NOT_FOUND, got 200"),
 ("removed post stays public", A, "\tif removed {\n\t\tpublic = false", "\tif removed && false {\n\t\tpublic = false", "TestChannelLifecycle", "want 404 E_NOT_FOUND, got 200"),
 ("removed post: any authed key may fetch", A, "allowed = !s.banned && (s.mod || key == ob.From)", "allowed = !s.banned && (s.mod || key == ob.From || true)", "TestChannelLifecycle", "want 404 E_NOT_FOUND, got 200"),
 ("kill switch ignores withdrawn enroll", H, "if len(mine) > 0 && mine[len(mine)-1].GrantID == gid {", "if len(mine) > 0 && mine[len(mine)-1].GrantID == gid && !mine[len(mine)-1].Revoked {", "TestKillSwitchSurvivesSelfWithdrawal", "want 403 E_REVOKED, got 200"),
 ("kill switch hits key that moved on", H, "if len(mine) > 0 && mine[len(mine)-1].GrantID == gid {", "if len(mine) > 0 {", "TestKillSwitchSparesKeyThatMovedOn", "submit rejected: 403"),
 ("binding end keeps allow entries", H, "\treturn ops.ClearAllowFor(en.Agent)\n", "\treturn nil\n", "TestTrustDoesNotTravel", "allow survived the binding"),
 ("own enroll revoke does not end binding", H, "\t\t\t\t\t\tif err := endBinding(ops, en, now); err != nil {", "\t\t\t\t\t\tif err := error(nil); err != nil {", "TestTrustDoesNotTravel", "after own revoke"),
 ("expiry not swept on submit", H, "\t\tif err := sweepExpired(ops, now); err != nil {", "\t\tif err := error(nil); err != nil {", "TestTrustDoesNotTravel", "after expiry"),
 ("expiry not swept before allow write", A, "\t\tif err := sweepExpired(ops, h.nowMS()); err != nil {", "\t\tif err := error(nil); err != nil {", "TestTrustDoesNotTravel", "allow made after expiry was cleared"),
 ("binding end processed repeatedly (revoke)", H, "\tif en.Ended {\n\t\treturn nil", "\tif en.Ended && false {\n\t\treturn nil", "TestKillSwitchSparesKeyThatMovedOn", "cleared trust given to its new binding"),
 # --- spec PR #3 alignment ---
 ("a: required auth failure not mapped to 401", A, "\tif err != nil && errors.As(err, &he) && he.code != ERevoked && he.status < 500 {", "\tif err != nil && errors.As(err, &he) && he.code != ERevoked && he.status < 500 && false {", "TestAuthReplayRejected", "want 401 E_AUTH, got 403"),
 ("a: revoked signer mapped to 401", A, "errors.As(err, &he) && he.code != ERevoked && he.status < 500 {", "errors.As(err, &he) && he.status < 500 {", "TestRevokedAgentRejected", "want 403 E_REVOKED, got 401"),
 ("a: optional-auth object failure leaks E_AUTH", A, '\t\tif key == "" {\n\t\t\twriteErr(w, notFound("no such object"))', '\t\tif key == "" {\n\t\t\twriteErr(w, &hubErr{http.StatusUnauthorized, EAuth, "x"})', "TestDirectObjectVisibility", "want 404 E_NOT_FOUND, got 401"),
 ("b: bad cursor E_SCHEMA", A, 'badRequest(EQuery, "bad cursor")', 'badRequest(clankmail.ESchema, "bad cursor")', "TestInboxCursorPaging", "want 400 E_QUERY, got 400"),
 ("b: bad queue E_SCHEMA", A, 'badRequest(EQuery, "queue must be inbox or requests")', 'badRequest(clankmail.ESchema, "queue must be inbox or requests")', "TestInboxCursorPaging", "want 400 E_QUERY, got 400"),
 ("b: bad limit E_SCHEMA", A, 'badRequest(EQuery, "limit must be 1–200")', 'badRequest(clankmail.ESchema, "limit must be 1–200")', "TestInboxCursorPaging", "want 400 E_QUERY, got 400"),
 ("b: bad sort E_SCHEMA", A, 'badRequest(EQuery, "sort must be active, new or members")', 'badRequest(clankmail.ESchema, "sort must be active, new or members")', "TestInboxCursorPaging", "want 400 E_QUERY, got 400"),
 ("c: slug uniqueness off", H, '\t\tif c != "" && c != id {', '\t\tif c != "" && c != id && false {', "TestSlugUniqueness", "want 403 E_FORBIDDEN, got"),
 ("c: own slug counts as taken", H, '\t\tif c != "" && c != id {', '\t\tif c != "" {', "TestSlugUniqueness", "submit rejected: 403"),
 ("c: update does not release old slug", H, "\t\tif err := ops.UnbindSlug(cur.Slug); err != nil {", "\t\tif err := error(nil); err != nil {", "TestSlugUniqueness", "want 404 E_NOT_FOUND, got 200"),
 ("c: update does not bind new slug", H, "\t\treturn ops.BindSlug(next.Slug, cur.ID)\n", "\t\treturn nil\n", "TestSlugUniqueness", "#golang"),
 ("d: unban skips the mod check", H, '\t\t} else if !s.mod {\n\t\t\treturn nil, forbidden("only the owner or a mod may ban")', '\t\t} else if !s.mod && false {\n\t\t\treturn nil, forbidden("only the owner or a mod may ban")', "TestBanRanksAndUnban", "want 403 E_FORBIDDEN, got 200 map[id"),
 ("grant name: unique only per agent (old rule)", H, "\t\t\tif g.Name == str(\"name\") && grantLive(&g, now) {", "\t\t\tif g.Name == str(\"name\") && grantLive(&g, now) && g.Agent != str(\"agent\") {", "TestGrantNameUniquePerPrincipal", "want 403 E_FORBIDDEN, got 200"),
 # --- §6.3 rule 2 cooldown ---
 # --- §6.3 rule 2 cooldown (any non-kill end, different principal only) ---
 ("cooldown: off", H, "} else if prev != nil && now < prev.EndedAt+enrollCooldownMS {", "} else if prev != nil && now < prev.EndedAt+enrollCooldownMS && false {", "TestEnrollCooldownAfterWithdrawal", "want 403 E_FORBIDDEN, got 200"),
 ("cooldown: off (inside-window kill)", H, "} else if prev != nil && now < prev.EndedAt+enrollCooldownMS {", "} else if prev != nil && now < prev.EndedAt+enrollCooldownMS && false {", "TestOwnerRevokeInsideCooldownKills", "want 403 E_FORBIDDEN, got 200"),
 ("cooldown: 24h-2s", H, "enrollCooldownMS = 86_400_000", "enrollCooldownMS = 86_398_000", "TestEnrollCooldownAfterWithdrawal", "want 403 E_FORBIDDEN, got 200"),
 ("cooldown: 24h+2s", H, "enrollCooldownMS = 86_400_000", "enrollCooldownMS = 86_402_000", "TestEnrollCooldownAfterWithdrawal", "submit rejected: 403"),
 ("cooldown: inclusive end +1s", H, "now < prev.EndedAt+enrollCooldownMS {", "now <= prev.EndedAt+enrollCooldownMS+1000 {", "TestEnrollCooldownAfterWithdrawal", "submit rejected: 403"),
 ("cooldown: withdrawal end not timed", H, "\t\t\t\t\t\tif err := endBinding(ops, en, now); err != nil {", "\t\t\t\t\t\tif err := endBinding(ops, en, 0); err != nil {", "TestEnrollCooldownAfterWithdrawal", "want 403 E_FORBIDDEN, got 200"),
 ("cooldown: only withdrawals count (expiry exempt, old rule)", H, "} else if prev != nil && now < prev.EndedAt+enrollCooldownMS {", "} else if prev != nil && prev.Revoked && now < prev.EndedAt+enrollCooldownMS {", "TestCooldownAfterExpiryAndRenewal", "want 403 E_FORBIDDEN, got 200"),
 ("cooldown: same principal also delayed (withdrawal)", H, "if pg == nil || pg.Principal != g.Principal {", "if pg == nil || pg.Principal != g.Principal || true {", "TestSamePrincipalReenrollAfterWithdrawal", "submit rejected: 403"),
 ("cooldown: same principal also delayed (expiry renewal)", H, "if pg == nil || pg.Principal != g.Principal {", "if pg == nil || pg.Principal != g.Principal || true {", "TestCooldownAfterExpiryAndRenewal", "submit rejected: 403"),
 ("cooldown: expiry end dated late, not at exp", H, "if err := endBinding(ops, en, g.Exp); err != nil {", "if err := endBinding(ops, en, g.Exp+5000); err != nil {", "TestCooldownAfterExpiryAndRenewal", "submit rejected: 403"),
 ("kill switch ignores withdrawn enroll (inside cooldown)", H, "if len(mine) > 0 && mine[len(mine)-1].GrantID == gid {", "if len(mine) > 0 && mine[len(mine)-1].GrantID == gid && !mine[len(mine)-1].Revoked {", "TestOwnerRevokeInsideCooldownKills", "want 403 E_REVOKED, got 200"),
 # --- reply route cutoff ---
 ("reply route kept across binding end", H, "} else if prev != nil && orig.Recv <= prev.EndedAt {", "} else if prev != nil && orig.Recv <= prev.EndedAt && false {", "TestReplyRouteLostWhenBindingEnds", "went to inbox"),
 ("reply route: expiry end dated late", H, "if err := endBinding(ops, en, g.Exp); err != nil {", "if err := endBinding(ops, en, g.Exp+5000); err != nil {", "TestReplyRouteLostWhenBindingEnds", "reply to a post-expiry message went to requests"),
 ("reply route: never-bound treated as ended", H, "} else if prev != nil && orig.Recv <= prev.EndedAt {", "} else if prev == nil || orig.Recv <= prev.EndedAt {", "TestDirectQueuePlacement", "reply not in scout inbox"),
 # --- bans (§7.3) ---
 ("ban: rank check off", H, "if rank < curRank {", "if rank < curRank && false {", "TestBanRanksAndUnban", "want 403 E_FORBIDDEN, got 200"),
 ("ban: owner not ranked above mods", H, "\t\t\trank = 2\n", "\t\t\trank = 1\n", "TestBanRanksAndUnban", "want 403 E_FORBIDDEN, got 200"),
 ("ban: unban is a no-op", H, "return func() error { return ops.LiftBan(ch.ID, m) }, nil // unban", "return func() error { return nil }, nil // unban", "TestBanRanksAndUnban", "want 200, got 403"),
 ("ban: passed until on unbanned key accepted", H, '\t\tif passed {\n\t\t\treturn nil, forbidden("ban until has passed', '\t\tif passed && false {\n\t\t\treturn nil, forbidden("ban until has passed', "TestBanRanksAndUnban", "want 403 E_FORBIDDEN, got 200"),
 # --- members log requires auth ---
 ("log: failed auth not 401", A, "401 E_AUTH.\n\t\tkey, err := h.requireAuth(r, nil)", "401 E_AUTH.\n\t\tkey, err := h.authenticate(r, nil)", "TestMembersOnlyChannelLog", "want 401 E_AUTH, got 403"),
 # --- client address (§5) ---
 ("xff: trusted-proxy check off", H, "\tif h.trusted(ip) {\n\t\thops", "\tif h.trusted(ip) || true {\n\t\thops", "TestRateLimitIgnoresUntrustedForwardedFor", "want 429"),
 ("xff: leftmost (spoofable) hop used", H, "for i := len(hops) - 1; i >= 0; i-- {", "for i := 0; i < len(hops); i++ {", "TestRateLimitClientAddress", "want 429 E_RATE, got 200"),
 ("xff: trusted hops not skipped", H, "\t\t\tif !h.trusted(ip) {\n\t\t\t\tbreak", "\t\t\tif !h.trusted(ip) || true {\n\t\t\t\tbreak", "TestRateLimitClientAddress", "want 429 E_RATE, got 200"),
 ("ipv6 not grouped by /64", H, "\tif ip.Is6() {", "\tif ip.Is6() && false {", "TestRateLimitClientAddress", "want 429 E_RATE, got 200"),
 # --- client address header (-client-ip-header) ---
 ("ip header: trusted-peer check off (handler)", H, "\tif !h.trusted(peer) {", "\tif !h.trusted(peer) && false {", "TestClientIPHeaderIgnoredFromUntrustedPeer", "untrusted peer, spoofed header 203.0.113.3: got 200, want 429"),
 ("ip header: trusted-peer check off (unit)", H, "\tif !h.trusted(peer) {", "\tif !h.trusted(peer) && false {", "TestClientIPHeaderAddress", "untrusted peer, header ignored: clientAddr = \"203.0.113.7\""),
 ("ip header: repeated header line accepted", H, "\tif len(v) != 1 {", "\tif len(v) < 1 {", "TestClientIPHeaderAddress", "header repeated: clientAddr = \"203.0.113.7\""),
 ("ip header: zoned address accepted", H, "if err != nil || c.Zone() != \"\" {", "if err != nil || c.Zone() != \"\" && false {", "TestClientIPHeaderAddress", "header with zone: clientAddr"),
 ("ip header: XFF still walked", H, "\tif h.cfg.ClientIPHeader != \"\" {\n\t\treturn rateKey", "\tif h.cfg.ClientIPHeader != \"\" && false {\n\t\treturn rateKey", "TestClientIPHeaderAddress", "XFF ignored when header present"),
 ("ip header: XFF still walked (handler)", H, "\tif h.cfg.ClientIPHeader != \"\" {\n\t\treturn rateKey", "\tif h.cfg.ClientIPHeader != \"\" && false {\n\t\treturn rateKey", "TestClientIPHeaderSeparatesVisitorsBehindProxy", "visitor B #1 behind the same proxy: got 429, want 200"),
 ("ip header: no-trusted-proxies config accepted", H, "if cfg.ClientIPHeader != \"\" && len(cfg.TrustedProxies) == 0 {", "if cfg.ClientIPHeader != \"\" && len(cfg.TrustedProxies) == 0 && false {", "TestClientIPHeaderRequiresTrustedProxies", "want refusal"),
 ("b: bad allow body E_SCHEMA", A, 'badRequest(EQuery, `body must be {"key":"k_…"}`)', 'badRequest(clankmail.ESchema, `body must be {"key":"k_…"}`)', "TestInboxCursorPaging", "want 400 E_QUERY, got 400 map[detail:body must be"),
 # --- PR #2 audit round 1 ---
 ("R1-1: live ban does not override mod/member", H, "\tif b {\n\t\treturn standing{banned: true}, nil", "\tif b && false {\n\t\treturn standing{banned: true}, nil", "TestBannedModLosesPowers", "banned mod admit: want 403 E_FORBIDDEN, got 200"),
 ("R1-1: banned author keeps removed-post access", A, "allowed = !s.banned && (s.mod || key == ob.From)", "allowed = s.mod || key == ob.From", "TestBannedModLosesPowers", "banned author fetch of its removed post"),
 ("R1-1: banned author may still remove", H, "if s.banned || (obj.From != author && !s.mod) {", "if obj.From != author && !s.mod {", "TestBannedModLosesPowers", "banned author remove"),
 ("R1-2: per-key limit not charged for forbidden fresh submits", H, "\t\tif !h.keyRL.allow(now, obj.From) {", "\t\tif !h.keyRL.allow(now, obj.From) && false {", "TestForbiddenSubmitsChargeKeyLimitRetriesDoNot", "want 429 E_RATE, got 403"),
 ("R1-2: per-address limit not charged before verification", H, "\tif !h.ipRL.allow(h.nowMS(), h.clientAddr(r)) {", "\tif !h.ipRL.allow(h.nowMS(), h.clientAddr(r)) && false {", "TestMalformedSubmitsChargeAddressLimit", "want 429 E_RATE, got 200"),
 ("R1-3: stored tokens re-verified", H, "\tvar f map[string]any\n\tif json.Unmarshal(b, &f) != nil {", "\tvar f map[string]any\n\tif _, err := clankmail.Verify(token); err != nil {\n\t\treturn m\n\t}\n\tif json.Unmarshal(b, &f) != nil {", "TestStoredTokensAreNotReverified", "reply rule re-verified the stored message"),
 ("R1-4: auth freshness checked against a pre-transaction now", A, "\terr := h.cfg.Store.Tx(r.Context(), func(ops Ops) error {\n\t\t// Freshness, pruning and the replay check share one `now`, read\n\t\t// inside the (serialised) transaction. Otherwise a request that\n\t\t// passed freshness and then waited could find its id pruned by a\n\t\t// later request and be accepted as new: a replay.\n\t\tnow := h.nowMS()\n\t\tif absDiff(ts, now) > authWindowMS {", "\tbefore := h.nowMS()\n\terr := h.cfg.Store.Tx(r.Context(), func(ops Ops) error {\n\t\tnow := h.nowMS()\n\t\tif absDiff(ts, before) > authWindowMS {", "TestAuthReplayCannotSlipPastPrune", "want 401 E_AUTH, got 200"),
 ("R1-5: malformed m_ id is 404", A, 'writeErr(w, badRequest(EQuery, "want an m_ id"))', 'writeErr(w, notFound("no such object"))', "TestMalformedPathParams", "/v1/objects/m_bad: want 400 E_QUERY, got 404"),
 ("R1-5: handle name not checked", A, "\tif !reHandleName.MatchString(name) {", "\tif !reHandleName.MatchString(name) && false {", "TestMalformedPathParams", "/v1/handles/A!: want 400 E_QUERY, got 404"),
 ("R1-5: channel ref not checked", A, '\tif err := checkChannelRef(r.PathValue("ref")); err != nil {', '\tif err := checkChannelRef(r.PathValue("ref")); err != nil && false {', "TestMalformedPathParams", "/v1/channels/c_bad: want 400 E_QUERY, got 404"),
 ("R1-5: malformed c_ id accepted as a ref", A, '\t\tif !validID("c_", ref) {', '\t\tif !validID("c_", ref) && false {', "TestMalformedPathParams", "/v1/channels/c_bad: want 400 E_QUERY, got 404"),
 ("R1-5: slug grammar not checked", A, '\tif !reSlugName.MatchString(strings.TrimPrefix(ref, "#")) {', '\tif !reSlugName.MatchString(strings.TrimPrefix(ref, "#")) && false {', "TestMalformedPathParams", "want 400 E_QUERY, got 404"),
 ("R1-5: log c_ id not checked", A, '\tif !validID("c_", r.PathValue("id")) {', '\tif !validID("c_", r.PathValue("id")) && false {', "TestMalformedPathParams", "/v1/channels/c_bad/log: want 400 E_QUERY, got 404"),
 # --- PR #2 audit round 2 ---
 ("R2: key charged before the stored-id check (replay drain)", H, "\t\tif prev, err := ops.Object(obj.ID); err != nil || prev != nil {\n\t\t\treturn err\n\t\t}\n\t\tif absDiff(obj.Fields[\"ts\"].(int64), now) > submitWindowMS {\n\t\t\treturn badRequest(EStale, \"ts outside ±300 s of hub time\")\n\t\t}\n\t\t// A fresh token may still be a replay: anyone holding it (another\n\t\t// hub's operator, a reader of a channel) can resend it within the\n\t\t// window. What is true here is that this id has not been charged\n\t\t// before: stored ids returned above, and charged-then-refused ids\n\t\t// are answered from memory. So the key is charged once per token,\n\t\t// and forbidden fresh submissions still pay that once.\n\t\tif rj, ok := h.rejected[obj.ID]; ok {\n\t\t\treturn rj.err\n\t\t}\n\t\tif !h.keyRL.allow(now, obj.From) {\n\t\t\treturn &hubErr{http.StatusTooManyRequests, ERate, \"rate limit exceeded (signer key)\"}\n\t\t}\n\t\tcharged = true\n", "\t\t// A fresh token may still be a replay: anyone holding it (another\n\t\t// hub's operator, a reader of a channel) can resend it within the\n\t\t// window. What is true here is that this id has not been charged\n\t\t// before: stored ids returned above, and charged-then-refused ids\n\t\t// are answered from memory. So the key is charged once per token,\n\t\t// and forbidden fresh submissions still pay that once.\n\t\tif rj, ok := h.rejected[obj.ID]; ok {\n\t\t\treturn rj.err\n\t\t}\n\t\tif !h.keyRL.allow(now, obj.From) {\n\t\t\treturn &hubErr{http.StatusTooManyRequests, ERate, \"rate limit exceeded (signer key)\"}\n\t\t}\n\t\tcharged = true\n\t\tif prev, err := ops.Object(obj.ID); err != nil || prev != nil {\n\t\t\treturn err\n\t\t}\n\t\tif absDiff(obj.Fields[\"ts\"].(int64), now) > submitWindowMS {\n\t\t\treturn badRequest(EStale, \"ts outside ±300 s of hub time\")\n\t\t}\n", "TestReplayCannotDrainVictimKeyLimit", "want 200, got 429"),
 ("R2: key charged before the stored-id check (retries drain)", H, "\t\tif prev, err := ops.Object(obj.ID); err != nil || prev != nil {\n\t\t\treturn err\n\t\t}\n\t\tif absDiff(obj.Fields[\"ts\"].(int64), now) > submitWindowMS {\n\t\t\treturn badRequest(EStale, \"ts outside ±300 s of hub time\")\n\t\t}\n\t\t// A fresh token may still be a replay: anyone holding it (another\n\t\t// hub's operator, a reader of a channel) can resend it within the\n\t\t// window. What is true here is that this id has not been charged\n\t\t// before: stored ids returned above, and charged-then-refused ids\n\t\t// are answered from memory. So the key is charged once per token,\n\t\t// and forbidden fresh submissions still pay that once.\n\t\tif rj, ok := h.rejected[obj.ID]; ok {\n\t\t\treturn rj.err\n\t\t}\n\t\tif !h.keyRL.allow(now, obj.From) {\n\t\t\treturn &hubErr{http.StatusTooManyRequests, ERate, \"rate limit exceeded (signer key)\"}\n\t\t}\n\t\tcharged = true\n", "\t\t// A fresh token may still be a replay: anyone holding it (another\n\t\t// hub's operator, a reader of a channel) can resend it within the\n\t\t// window. What is true here is that this id has not been charged\n\t\t// before: stored ids returned above, and charged-then-refused ids\n\t\t// are answered from memory. So the key is charged once per token,\n\t\t// and forbidden fresh submissions still pay that once.\n\t\tif rj, ok := h.rejected[obj.ID]; ok {\n\t\t\treturn rj.err\n\t\t}\n\t\tif !h.keyRL.allow(now, obj.From) {\n\t\t\treturn &hubErr{http.StatusTooManyRequests, ERate, \"rate limit exceeded (signer key)\"}\n\t\t}\n\t\tcharged = true\n\t\tif prev, err := ops.Object(obj.ID); err != nil || prev != nil {\n\t\t\treturn err\n\t\t}\n\t\tif absDiff(obj.Fields[\"ts\"].(int64), now) > submitWindowMS {\n\t\t\treturn badRequest(EStale, \"ts outside ±300 s of hub time\")\n\t\t}\n", "TestForbiddenSubmitsChargeKeyLimitRetriesDoNot", "want 200, got 429"),
 ("R2: key charged before freshness (stale replay drain)", H, "\t\tif prev, err := ops.Object(obj.ID); err != nil || prev != nil {\n\t\t\treturn err\n\t\t}\n\t\tif absDiff(obj.Fields[\"ts\"].(int64), now) > submitWindowMS {\n\t\t\treturn badRequest(EStale, \"ts outside ±300 s of hub time\")\n\t\t}\n\t\t// A fresh token may still be a replay: anyone holding it (another\n\t\t// hub's operator, a reader of a channel) can resend it within the\n\t\t// window. What is true here is that this id has not been charged\n\t\t// before: stored ids returned above, and charged-then-refused ids\n\t\t// are answered from memory. So the key is charged once per token,\n\t\t// and forbidden fresh submissions still pay that once.\n\t\tif rj, ok := h.rejected[obj.ID]; ok {\n\t\t\treturn rj.err\n\t\t}\n\t\tif !h.keyRL.allow(now, obj.From) {\n\t\t\treturn &hubErr{http.StatusTooManyRequests, ERate, \"rate limit exceeded (signer key)\"}\n\t\t}\n\t\tcharged = true\n", "\t\tif prev, err := ops.Object(obj.ID); err != nil || prev != nil {\n\t\t\treturn err\n\t\t}\n\t\t// A fresh token may still be a replay: anyone holding it (another\n\t\t// hub's operator, a reader of a channel) can resend it within the\n\t\t// window. What is true here is that this id has not been charged\n\t\t// before: stored ids returned above, and charged-then-refused ids\n\t\t// are answered from memory. So the key is charged once per token,\n\t\t// and forbidden fresh submissions still pay that once.\n\t\tif rj, ok := h.rejected[obj.ID]; ok {\n\t\t\treturn rj.err\n\t\t}\n\t\tif !h.keyRL.allow(now, obj.From) {\n\t\t\treturn &hubErr{http.StatusTooManyRequests, ERate, \"rate limit exceeded (signer key)\"}\n\t\t}\n\t\tcharged = true\n\t\tif absDiff(obj.Fields[\"ts\"].(int64), now) > submitWindowMS {\n\t\t\treturn badRequest(EStale, \"ts outside ±300 s of hub time\")\n\t\t}\n", "TestReplayCannotDrainVictimKeyLimit", "want 400 E_STALE, got 429"),
 ("R2: storedFields case-insensitive struct decode", H, "\tvar f map[string]any\n\tif json.Unmarshal(b, &f) != nil {\n\t\treturn m\n\t}\n\tm.Re, _ = f[\"re\"].(string)\n\tm.To = strList(f[\"to\"])\n\treturn m", "\tjson.Unmarshal(b, &m)\n\treturn m", "TestStoredFieldsReadExactKeys", "bob (in to) fetching his DM: want 200"),
 # --- PR #2 audit round 3 (final) ---
 ("R3: refused token ids forgotten (each replay charges again)", H, "\t\tif charged && errors.As(err, &he) && he.status < 500 {", "\t\tif charged && errors.As(err, &he) && he.status < 500 && false {", "TestRejectedReplayCannotDrainVictimKeyLimit", "want 403 E_FORBIDDEN, got 429"),
 ("R3: remembered refusal not consulted", H, "\t\tif rj, ok := h.rejected[obj.ID]; ok {", "\t\tif rj, ok := h.rejected[obj.ID]; ok && false {", "TestRejectedReplayCannotDrainVictimKeyLimit", "want 403 E_FORBIDDEN, got 429"),
 ("R3: auth refusal after the key charge", H, 'if obj.Type == "auth" {', 'if obj.Type == "auth" && false {', "TestRejectedReplayCannotDrainVictimKeyLimit", "want 403 E_FORBIDDEN, got 429"),
 # --- subscriptions (§7.4) ---
 ("sub: unknown channel not 404", D, '\t\treturn nil, notFound("unknown channel")\n\t}\n\tif ok, err := mayRead(', '\t\treturn nil, forbidden("unknown channel")\n\t}\n\tif ok, err := mayRead(', "TestSubAcceptance", "want 404 E_NOT_FOUND, got 403"),
 ("sub: members channel without membership", D, '\t} else if !ok {\n\t\treturn nil, forbidden("a read=members', '\t} else if !ok && false {\n\t\treturn nil, forbidden("a read=members', "TestDigestMembersOnlyChannel", "want 403 E_FORBIDDEN, got 200"),
 ("sub: mayRead treats members as public", H, '\tif ch.Read == "public" {\n\t\treturn true, nil', '\tif ch.Read == "public" || true {\n\t\treturn true, nil', "TestDigestMembersOnlyChannel", "want 403 E_FORBIDDEN, got 200"),
 ("sub: duplicate live sub accepted", D, "\t} else if cur != nil {", "\t} else if cur != nil && false {", "TestSubAcceptance", "want 403 E_FORBIDDEN, got"),
 ("sub: live cap off", D, "\tif len(live) >= maxLiveSubs {", "\tif len(live) >= maxLiveSubs && false {", "TestSubAcceptance", "want 429 E_RATE, got 200"),
 ("sub: live cap off by one (101)", D, "\tif len(live) >= maxLiveSubs {", "\tif len(live) > maxLiveSubs {", "TestSubAcceptance", "want 429 E_RATE, got 200"),
 ("sub: replays history (start 0)", D, "StartSeq: head})", "StartSeq: 0 * head})", "TestDigestEligibilityAndRanking", "bob's digest: got"),
 ("sub: public by id", A, '\tif ob.Type == "sub" {\n\t\tpublic = false', '\tif ob.Type == "sub" && false {\n\t\tpublic = false', "TestSubAcceptance", "want 404 E_NOT_FOUND, got 200"),
 ("sub: revoke not applied", H, "\t\t\t\treturn ops.RevokeSub(target.ID)\n", "\t\t\t\treturn nil\n", "TestRevokedSubStopsDelivery", "after revoke: got"),
 ("sub: not revocable", H, ' || target.Type == "sub")', ')', "TestRevokedSubStopsDelivery", "submit rejected: 403"),
 ("subs: auth not required", D, "func (h *Hub) handleSubs(w http.ResponseWriter, r *http.Request) {\n\tkey, err := h.requireAuth(r, nil)\n\tif err != nil {", "func (h *Hub) handleSubs(w http.ResponseWriter, r *http.Request) {\n\tkey, err := h.requireAuth(r, nil)\n\tif err != nil && false {", "TestSubAcceptance", "want 401 E_AUTH, got 200"),
 # --- digest (§8.1) ---
 ("digest: auth not required", D, "\tkey, err := h.requireAuth(r, nil)\n\tif err != nil {\n\t\twriteErr(w, err)\n\t\treturn\n\t}\n\tif !h.digKeyRL", "\tkey, err := h.requireAuth(r, nil)\n\tif err != nil && false {\n\t\twriteErr(w, err)\n\t\treturn\n\t}\n\tif !h.digKeyRL", "TestSubAcceptance", "want 401 E_AUTH, got 200"),
 ("digest r1: hidden posts served", S, "l.hidden=0 AND l.author!=? AND NOT EXISTS", "1=1 AND l.author!=? AND NOT EXISTS", "TestDigestEligibilityAndRanking", "bob's digest: got"),
 ("digest r2: revoked sub still delivers", S, "o.subs(`key=? AND revoked=0`, key)", "o.subs(`key=? AND 1=1`, key)", "TestRevokedSubStopsDelivery", "after revoke: got"),
 ("digest r2: posts before the sub served", D, "lo: max(after, s.StartSeq)", "lo: max(after, 0*s.StartSeq)", "TestDigestEligibilityAndRanking", "bob's digest: got"),
 ("digest r3: unreadable channel scanned (readability filter off)", D, "} else if ok {\n\t\t\tstreams = append(", "} else if ok || true {\n\t\t\tstreams = append(", "TestDigestMembersOnlyChannel", "after leave: got"),
 ("digest r3: unreadable channel scanned (cost)", D, "} else if ok {\n\t\t\tstreams = append(", "} else if ok || true {\n\t\t\tstreams = append(", "TestDigestScanCost", "unreadable channel: read ["),
 ("digest r4: own posts served", S, "l.author!=? AND NOT EXISTS", "(l.author!=? OR 1) AND NOT EXISTS", "TestDigestEligibilityAndRanking", "bob's digest: got"),
 ("digest r5: banned author served", S, "b.key=l.author AND ` + banLiveSQL", "b.key=l.author AND 0 AND ` + banLiveSQL", "TestDigestEligibilityAndRanking", "bob's digest: got"),
 ("digest ban: forever ban not live (SQL)", H, "const banLiveSQL = `(b.until=0 OR b.until>?)`", "const banLiveSQL = `(0 OR b.until>?)`", "TestDigestEligibilityAndRanking", "bob's digest: got"),
 ("digest ban: until boundary >= (SQL)", H, "const banLiveSQL = `(b.until=0 OR b.until>?)`", "const banLiveSQL = `(b.until=0 OR b.until>=?)`", "TestDigestBanExpiry", "at until: got"),
 ("digest counts: re not stored on append", H, "ops.AppendLog(ch.ID, obj.ID, re, now)", "ops.AppendLog(ch.ID, obj.ID, re[:0], now)", "TestDigestEligibilityAndRanking", "bob's digest: got"),
 ("digest cursor: does not advance past examined rows", D, "\t\ttop.buf = top.buf[1:]\n\t\tnext = row.Seq\n", "\t\ttop.buf = top.buf[1:]\n\t\tnext = next + 0*row.Seq\n", "TestDigestScanCost", "pages (read, next, more, items)"),
 ("digest cursor: not moved to head when every log is read", D, "\t\t\tnext = max(next, head)\n", "\t\t\tnext = max(next, 0*head)\n", "TestDigestScanCost", "unreadable channel: read [0]"),
 ("digest cursor: budget stop treated as end of log (skips posts)", D, "\t\t\t\t\tmore = true // budget spent with rows left to read\n\t\t\t\t\tbreak scan\n", "\t\t\t\t\tif h, _ := ops.LogHead(); h > 0 {\n\t\t\t\t\t\tnext = h // budget spent with rows left to read\n\t\t\t\t\t}\n\t\t\t\t\tbreak scan\n", "TestDigestPagesCoverEveryPostOnce", "pages covered"),
 ("digest merge: not in cursor order", D, "st.buf[0].Seq < top.buf[0].Seq", "st.buf[0].Seq > top.buf[0].Seq", "TestDigestPagesCoverEveryPostOnce", "pages covered"),
 ("digest budget: 2000 -> 2001", D, "digestScanBudget   = 2000", "digestScanBudget   = 2001", "TestDigestScanCost", "pages (read, next, more, items)"),
 ("digest budget: off (2000 -> 1<<30)", D, "digestScanBudget   = 2000", "digestScanBudget   = 1 << 30", "TestDigestScanCost", "pages (read, next, more, items)"),
 ("digest window: never cut", D, "\t\t\tif len(win) == digestWindow {", "\t\t\tif len(win) == digestWindow && false {", "TestDigestWindow", "first window"),
 ("digest window: 999", D, "digestWindow       = 1000", "digestWindow       = 999 ", "TestDigestWindow", "first window"),
 ("digest window: stream ends after one batch", D, "st.buf, st.done = rows, len(rows) < n", "st.buf, st.done = rows, len(rows) <= n", "TestDigestWindow", "first window"),
 ("digest memory: token read for every window post", D, "\t\t\twin = append(win, winPost{row, top.ch})\n", "\t\t\twin = append(win, winPost{row, top.ch})\n\t\t\tif ob, _ := ops.Object(row.ID); ob != nil {\n\t\t\t\tdefer func(string) {}(ob.Token)\n\t\t\t}\n", "TestDigestMemoryBounded", "one digest allocated"),
 ("digest plan: scan needs a sort", S, "WHERE l.channel=? AND l.seq>? ORDER BY l.seq LIMIT ?", "WHERE l.channel=? AND l.seq>? ORDER BY l.recv, l.seq LIMIT ?", "TestDigestQueryPlans", "scan plan sorts or scans"),
 ("migration: (channel, re) index not created", S, "db.Exec(`CREATE INDEX IF NOT EXISTS chan_log_re ON chan_log(channel, re)`)", "db.Exec(`SELECT 1`)", "TestLogReMigration", "submit rejected: 500 map[detail:internal error"),  # replies seek it by INDEXED BY, so a missing index fails the first reply
 ("digest rate limit: per key off", D, "\tif !h.digKeyRL.allow(h.nowMS(), key) {", "\tif !h.digKeyRL.allow(h.nowMS(), key) && false {", "TestDigestRateLimit", "key burst of 30: want 429 E_RATE, got 200"),
 ("digest rate limit: per address off", D, "\tif !h.digIPRL.allow(h.nowMS(), h.clientAddr(r)) {", "\tif !h.digIPRL.allow(h.nowMS(), h.clientAddr(r)) && false {", "TestDigestRateLimit", "address burst of 120: want 429 E_RATE, got 200"),
 ("digest rate limit: key burst 30 -> 31", "go/hub/ratelimit.go", "DefaultDigestKeyLimit = Limit{Burst: 30, PerSec: 0.5}", "DefaultDigestKeyLimit = Limit{Burst: 31, PerSec: 0.5}", "TestDigestRateLimit", "key burst of 30: want 429 E_RATE, got 200"),
 ("digest rate limit: key refill 0.5/s -> 1/s", "go/hub/ratelimit.go", "DefaultDigestKeyLimit = Limit{Burst: 30, PerSec: 0.5}", "DefaultDigestKeyLimit = Limit{Burst: 30, PerSec: 1}", "TestDigestRateLimit", "key refill of 0.5/s: want 429 E_RATE, got 200"),
 ("digest rate limit: address burst 120 -> 121", "go/hub/ratelimit.go", "DefaultDigestIPLimit  = Limit{Burst: 120, PerSec: 2}", "DefaultDigestIPLimit  = Limit{Burst: 121, PerSec: 2}", "TestDigestRateLimit", "address burst of 120: want 429 E_RATE, got 200"),
 ("digest query: limit 51 accepted", D, "if perr != nil || n < 1 || n > digestMaxParam {", "if perr != nil || n < 1 {", "TestDigestCursor", "want 400 E_QUERY, got 200"),
 ("digest query: default per_channel 5 -> 6", D, "digestDefaultPerCh = 5", "digestDefaultPerCh = 6", "TestDigestDefaultsAndCaps", "?: got"),
 ("digest query: default limit 20 -> 21", D, "digestDefaultLimit = 20", "digestDefaultLimit = 21", "TestDigestDefaultsAndCaps", "?per_channel=50: got"),
 ("migration: re not backfilled", S, "fill[seq] = storedFields(tok).Re", "fill[seq] = storedFields(tok).Re[:0]", "TestLogReMigration", "migrated digest"),
 ("log: members check bypassed via mayRead", A, "\t\t\tok, err = mayRead(ops, ch, key, h.nowMS())\n", "\t\t\tok, err = key == key, nil\n", "TestMembersOnlyChannelLog", "want 403 E_FORBIDDEN, got 200"),
 # --- stored reply counters (§8.1) ---
 ("counters: reply not counted on append", S, "\tif re != \"\" {\n\t\tif err := o.countReply(channel, re, author, +1); err != nil {", "\tif re != \"\" && false {\n\t\tif err := o.countReply(channel, re, author, +1); err != nil {", "TestReplyCountersMatchRecount", "stored counters differ from the recount"),
 ("counters: replies not incremented (repliers are)", S, "SET replies=replies+?, repliers=repliers+?", "SET replies=replies+0*?, repliers=repliers+?", "TestReplyCountersMatchRecount", "reply_authors says"),  # caught by the chan_log/reply_authors consistency check
 ("counters: not decremented on remove", S, "\treturn o.countReply(channel, re, author, -1)\n", "\treturn o.countReply(channel, re, author, 0*-1)\n", "TestReplyCountersMatchRecount", "stored counters differ from the recount"),
 ("counters: re-remove decrements again", S, "\tif err != nil || !ok || hidden {\n\t\treturn err\n\t}\n\tif err := o.exec(`UPDATE chan_log SET hidden=1", "\tif err != nil || !ok {\n\t\treturn err\n\t}\n\tif err := o.exec(`UPDATE chan_log SET hidden=1", "TestReRemoveDecrementsOnce", "re-removing a reply: P stored [0 0], want [1 1]"),
 ("counters: replier dropped on any removal (multiplicity)", S, "\tcase d < 0 && n == 0:", "\tcase d < 0:", "TestReplyCountersMatchRecount", "reply_authors says"),
 ("counters: replier added on every reply (multiplicity)", S, "\tcase d > 0 && n == 1:", "\tcase d > 0:", "TestReplyCountersMatchRecount", "reply_authors says"),
 ("counters: self-reply counted (append)", S, "\tif err != nil || !ok || pa == author {", "\tif err != nil || !ok || pa == author && false {", "TestReplyCountersMatchRecount", "stored counters differ from the recount"),
 ("counters: self-reply counted (earlier replies)", S, "WHERE channel=? AND re=? AND hidden=0 AND author!=? GROUP BY author", "WHERE channel=? AND re=? AND hidden=0 AND (author!=? OR 1) GROUP BY author", "TestReplyCountersMatchRecount", "stored counters differ from the recount"),
 ("counters: cross-channel reply counted (append)", S, "\tpa, _, ok, err := o.LogEntry(channel, parent)\n", "\tvar pch string\n\tok, err := one(o.queryRow(`SELECT author, channel FROM chan_log WHERE obj_id=?`, parent), new(string), &pch)\n\tpa, _, _, _ := o.LogEntry(pch, parent)\n\tchannel = pch\n", "TestReplyCountersMatchRecount", "stored counters differ from the recount"),
 ("counters: earlier replies not counted for a new post", S, "WHERE channel=? AND re=? AND hidden=0 AND author!=? GROUP BY author", "WHERE channel=? AND re=? AND hidden=0 AND author!=? AND 0 GROUP BY author", "TestReplyCountersMatchRecount", "stored counters differ from the recount"),
 ("counters: hidden earlier replies counted for a new post", S, "WHERE channel=? AND re=? AND hidden=0 AND author!=? GROUP BY author", "WHERE channel=? AND re=? AND author!=? GROUP BY author", "TestReplyCountersMatchRecount", "stored counters differ from the recount"),
 ("recount: not run on open (first open)", S, "\tif err := recountReplies(tx); err != nil {", "\tif err := error(nil); err != nil && recountReplies(tx) != nil {", "TestReplyCountBackfill", "first open: back-filled counters differ from the recount"),
 ("recount: not run on open (after an older binary)", S, "\tif err := recountReplies(tx); err != nil {", "\tif err := error(nil); err != nil && recountReplies(tx) != nil {", "TestCountersRecountedAfterOlderBinary", "P's counted repliers [k_b k_e], want"),
 ("recount: before migrateLogRe (re NULL rows not counted)", S, "\tif err := migrateLogRe(db); err != nil {\n\t\tdb.Close()\n\t\treturn nil, err\n\t}\n\tif err := migrateReplyCounts(db); err != nil {\n\t\tdb.Close()\n\t\treturn nil, err\n\t}\n", "\tif err := migrateReplyCounts(db); err != nil {\n\t\tdb.Close()\n\t\treturn nil, err\n\t}\n\tif err := migrateLogRe(db); err != nil {\n\t\tdb.Close()\n\t\treturn nil, err\n\t}\n", "TestCountersRecountedAfterOlderBinary", "P's counted repliers [k_b k_c], want"),
 ("counters: decrement of an uncounted reply inserts n=-1", S, "ok, err := one(o.queryRow(`UPDATE reply_authors SET n=n+? WHERE post=? AND author=? RETURNING n`, d, parent, author), &n)", "ok, err := one(o.queryRow(`INSERT INTO reply_authors(post, author, n) VALUES(?,?,?)\n\t\tON CONFLICT(post, author) DO UPDATE SET n=n+excluded.n RETURNING n`, parent, author, d), &n)", "TestCountReplyDecrementFloor", "removing an uncounted reply: 1 reply_authors rows for P"),
 ("counters: decrement of an uncounted reply goes below zero", S, "\t\tif !ok {\n\t\t\treturn nil // not counted", "\t\tif !ok && false {\n\t\t\treturn nil // not counted", "TestCountReplyDecrementFloor", "m_P: chan_log counters [-1 -1], reply_authors says [0 0]"),
 ("back-fill: not from scratch", S, "\t\t`DELETE FROM reply_authors`,\n", "", "TestReplyCountBackfill", "UNIQUE constraint failed: reply_authors.post"),
 ("back-fill: stale counters not reset", S, "\t\t`UPDATE chan_log SET replies=0, repliers=0 WHERE replies!=0 OR repliers!=0`,\n", "", "TestReplyCountBackfill", "reply_authors says"),  # stale rows left at +7: the consistency check sees them
 ("back-fill: hidden reply counted", S, "WHERE r.hidden=0 AND r.re!='' AND r.author!=p.author", "WHERE r.re!='' AND r.author!=p.author", "TestReplyCountBackfill", "first open: back-filled counters differ from the recount"),
 ("back-fill: self-reply counted", S, "WHERE r.hidden=0 AND r.re!='' AND r.author!=p.author", "WHERE r.hidden=0 AND r.re!='' AND (r.author!=p.author OR 1)", "TestReplyCountBackfill", "first open: back-filled counters differ from the recount"),
 ("back-fill: cross-channel reply counted", S, "JOIN chan_log p ON p.channel=r.channel AND p.obj_id=r.re", "JOIN chan_log p ON p.obj_id=r.re", "TestReplyCountBackfill", "first open: back-filled counters differ from the recount"),
 ("digest: counters swapped on read", S, "&r.TS, &r.Replies, &r.Repliers, &r.Eligible", "&r.TS, &r.Repliers, &r.Replies, &r.Eligible", "TestDigestMatchesReference", "limit 50 per_channel 50:"),
 ("digest: counters not passed to ranking", D, "Repliers: p.Repliers, Replies: p.Replies}", "Repliers: 0 * p.Repliers, Replies: p.Replies}", "TestDigestEligibilityAndRanking", "bob's digest: got"),
 ("digest: per-request reply count (cost)", S, "ob.ts, l.replies, l.repliers,", "ob.ts, (SELECT COUNT(*) FROM chan_log r WHERE r.channel=l.channel AND r.re=l.obj_id AND r.hidden=0 AND r.author!=l.author), l.repliers,", "TestDigestCostIndependentOfReplies", "digest time grows with replies"),
 ("digest: per-request reply count (plan)", S, "ob.ts, l.replies, l.repliers,", "ob.ts, (SELECT COUNT(*) FROM chan_log r WHERE r.channel=l.channel AND r.re=l.obj_id AND r.hidden=0 AND r.author!=l.author), l.repliers,", "TestDigestStatementPlans", "digest plan reads replies or scans"),
 ("submit: parent found by a channel scan", S, "SELECT author, hidden FROM chan_log INDEXED BY chan_log_obj WHERE", "SELECT author, hidden FROM chan_log INDEXED BY chan_log_channel WHERE", "TestSubmitPathPlans", "submit path scans"),
 ("cors: discovery loses its header", H, "publicCORS(h.handleDiscovery)", "h.handleDiscovery", "TestDiscoveryCORS", "(200): CORS headers map[], want exactly"),
 ("cors: credentials allowed on discovery", A, '\t\tw.Header().Set("Access-Control-Allow-Origin", "*")\n', '\t\tw.Header().Set("Access-Control-Allow-Origin", "*")\n\t\tw.Header().Set("Access-Control-Allow-Credentials", "true")\n', "TestDiscoveryCORS", "Access-Control-Allow-Credentials:true"),
 ("cors: channel lookup opened too", H, '"GET /v1/channels/{ref}", h.handleChannel)', '"GET /v1/channels/{ref}", publicCORS(h.handleChannel))', "TestNoCORSOutsideDiscovery", "(200): CORS headers map[Access-Control-Allow-Origin:*], want none"),
 ("cors: every endpoint opened", H, "func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) { h.mux.ServeHTTP(w, r) }", "func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {\n\tw.Header().Set(\"Access-Control-Allow-Origin\", \"*\")\n\th.mux.ServeHTTP(w, r)\n}", "TestNoCORSOutsideDiscovery", "POST /v1/submit (200): CORS headers map[Access-Control-Allow-Origin:*], want none"),
]

GO = os.path.realpath(shutil.which("go"))  # resolved once: a profile switch mid-run must not lose it
HUB = os.path.join(WORK, "go", "hub")

def run(test):
    p = subprocess.run([GO, "test", "-count=1", "-run", "^" + test + "$", "."],
                       cwd=HUB, capture_output=True, text=True,
                       env=dict(os.environ, CGO_ENABLED="0"))  # pure Go: no C toolchain to vanish mid-run
    return p.returncode, p.stdout + p.stderr

def checksum():
    h = hashlib.sha256()
    hub = os.path.join(SRC, "go", "hub")
    for name in sorted(os.listdir(hub)):
        if name.endswith(".go"):
            h.update(name.encode() + open(os.path.join(hub, name), "rb").read())
    return h.hexdigest()

def fresh():
    for x in ["go", "vectors"]:
        shutil.copytree(os.path.join(SRC, x), os.path.join(WORK, x))
    shutil.copy2(os.path.join(SRC, "go.mod"), WORK)

before = checksum()
fresh()
bad = 0
tests = sorted({m[4] for m in M})
for t in tests:
    rc, out = run(t)
    ok = rc == 0 and "\nok" in "\n" + out and "no tests to run" not in out
    print(f"CONTROL {t}: {'PASS' if ok else 'FAIL'}")
    if not ok:
        print(out); bad += 1
print()
killed = 0
for guard, f, old, new, test, want in M:
    path = os.path.join(WORK, f)
    orig = open(os.path.join(SRC, f)).read()
    n = orig.count(old)
    if n != 1:
        print(f"HARNESS {guard}: pattern occurs {n}x"); bad += 1; continue
    open(path, "w").write(orig.replace(old, new))
    rc, out = run(test)
    open(path, "w").write(orig)
    if "build failed" in out or "setup failed" in out:
        print(f"BUILD-FAIL       {guard}"); print(out[:800]); bad += 1; continue
    red = rc != 0 and ("--- FAIL: " + test) in out
    right = want in out
    status = "KILLED" if red and right else ("RED-WRONG-REASON" if red else "SURVIVED")
    if status == "KILLED":
        killed += 1
    else:
        bad += 1
    line = next((l.strip() for l in out.splitlines() if "_test.go:" in l), "")
    print(f"{status:16} {guard:52} -> {test}  [{line[:110]}]")
shutil.rmtree(WORK)
if checksum() != before:
    print("SOURCE CHANGED during the run"); bad += 1
print(f"\nkilled {killed}/{len(M)}, controls {len(tests)}, problems: {bad}")
sys.exit(1 if bad else 0)
