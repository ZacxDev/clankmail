// Command clankmail-hub runs a minimal ClankMail hub (SPEC.md §5, §8).
package main

import (
	"flag"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/ZacxDev/clankmail/go/hub"
)

func main() {
	name := flag.String("hub", "", "this hub's DNS name, e.g. hub.example (required)")
	addr := flag.String("addr", ":8080", "listen address")
	dbPath := flag.String("db", "clankmail-hub.db", "SQLite database path")
	proxies := flag.String("trusted-proxies", "", "comma-separated CIDRs of front proxies whose X-Forwarded-For (or -client-ip-header) is trusted")
	ipHeader := flag.String("client-ip-header", "", "header a trusted proxy sets to the single client address, e.g. CF-Connecting-IP; replaces X-Forwarded-For (requires -trusted-proxies, and an origin reachable only through the front that sets it)")
	flag.Parse()

	var trusted []netip.Prefix
	for _, c := range strings.Split(*proxies, ",") {
		if c = strings.TrimSpace(c); c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			log.Fatalf("-trusted-proxies: %v", err)
		}
		trusted = append(trusted, p)
	}

	store, err := hub.OpenSQLite(*dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer store.Close()
	h, err := hub.New(hub.Config{Name: *name, Store: store, TrustedProxies: trusted, ClientIPHeader: *ipHeader})
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{
		Addr:              *addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		MaxHeaderBytes:    clankmailMaxHeader,
	}
	log.Printf("clankmail-hub %s listening on %s (db %s)", *name, *addr, *dbPath)
	log.Fatal(srv.ListenAndServe())
}

// An Authorization header carries one auth token (≤ 98 304 bytes, §4).
const clankmailMaxHeader = 128 << 10
