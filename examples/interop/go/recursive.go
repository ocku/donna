// Standard-library client against Donna's iterative resolver and its cache.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"
)

func main() {
	address := os.Getenv("RECURSIVE_ADDRESS")
	if address == "" {
		address = "172.29.53.11:5301"
	}
	var tcp atomic.Int32
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		if network == "tcp" {
			tcp.Add(1)
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
	}}
	for repeat := 0; repeat < 2; repeat++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		for _, name := range []string{"www.example.test.", "alias.example.test."} {
			addresses, err := resolver.LookupIP(ctx, "ip4", name)
			if err != nil || len(addresses) != 1 || !addresses[0].Equal(net.ParseIP("192.0.2.80")) {
				panic(fmt.Sprintf("%s: addresses=%v error=%v", name, addresses, err))
			}
		}
		// Go exposes both NXDOMAIN and NODATA as IsNotFound. The raw Python
		// matrix independently checks their distinct wire RCODEs and SOAs.
		for _, name := range []string{"missing.example.test.", "text.example.test."} {
			addresses, err := resolver.LookupIP(ctx, "ip4", name)
			failure, ok := err.(*net.DNSError)
			if len(addresses) != 0 || !ok || !failure.IsNotFound {
				panic(fmt.Sprintf("%s: expected not-found, addresses=%v error=%v", name, addresses, err))
			}
		}
		addresses, err := resolver.LookupIP(ctx, "ip4", "many.example.test.")
		if err != nil || len(addresses) != 96 {
			panic(fmt.Sprintf("large RRset: addresses=%v error=%v", addresses, err))
		}
		seen := make(map[string]bool)
		for _, address := range addresses {
			seen[address.String()] = true
		}
		for i := 1; i <= 96; i++ {
			if !seen[fmt.Sprintf("192.0.2.%d", i)] {
				panic("incomplete large RRset")
			}
		}
		cancel()
	}
	if tcp.Load() == 0 {
		panic("large response did not exercise TCP fallback")
	}
	fmt.Println("PASS Go recursive positive, alias, NXDOMAIN/NODATA, complete RRset and TCP fallback; repeated queries")
}
