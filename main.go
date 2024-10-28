package main

import (
	"bufio"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/seancfoley/ipaddress-go/ipaddr"
)

func memusage() {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("Alloc = %v MiB\n", m.Alloc/1024/1024)
	// write mem.prof
	f, err := os.Create("mem.prof")
	if err != nil {
		log.Fatal(err)
	}
	pprof.WriteHeapProfile(f)
	f.Close()
}
func randomBytes() [4]byte {
	var b [4]byte
	for i := 0; i < 4; i++ {
		b[i] = byte(rand.Uint32())
	}
	return b
}

func main() {
	// Create a new ASN trie
	lookup := NewASNTrie()

	filename := "ip2asn-v4.tsv"
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	scanner := bufio.NewScanner(f)

	// Parse and add each record
	for scanner.Scan() {
		err := lookup.AddRecord(scanner.Text())
		if err != nil {
			fmt.Printf("Error adding record: %v\n", err)
			continue
		}
	}
	memusage()

	ips := []net.IP{}
	count := 50000
	for i := 0; i < count; i++ {
		// create a random IPv6 address
		bytes := randomBytes()
		ip := net.IP(bytes[:])
		ips = append(ips, ip)
	}

	now := time.Now()
	success := 0
	for _, ip := range ips {
		_, err = lookup.LookupIP(ip)
		if err == nil {
			success++
		}
	}
	// print programs' memory usage

	fmt.Println(success)
	elapsed := time.Since(now)
	fmt.Println("number per second", float64(count)/elapsed.Seconds())

}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

// ASNInfo holds the metadata for an IP range
type ASNInfo struct {
	ASN     int
	Country string
	Network string
}

// ASNTrie wraps the library's trie for ASN lookups
type ASNTrie struct {
	trie *ipaddr.AssociativeTrie[*ipaddr.IPAddress, *ASNInfo]
}

// NewASNTrie creates a new ASN lookup trie
func NewASNTrie() *ASNTrie {
	return &ASNTrie{
		trie: ipaddr.NewAssociativeTrie[*ipaddr.IPAddress, *ASNInfo](),
	}
}

// AddRecord parses a line of ASN data and adds it to the trie
func (t *ASNTrie) AddRecord(line string) error {
	// Split the line into fields
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return fmt.Errorf("invalid record format: %s", line)
	}

	// Parse start and end IPs
	startIP := ipaddr.NewIPAddressString(fields[0])
	endIP := ipaddr.NewIPAddressString(fields[1])

	startAddr, err := startIP.ToAddress()
	if err != nil {
		return fmt.Errorf("error parsing start IP: %v", err)
	}

	endAddr, err := endIP.ToAddress()
	if err != nil {
		return fmt.Errorf("error parsing end IP: %v", err)
	}

	// Parse ASN (removing any "AS" prefix if present)
	asnStr := fields[2]
	asn, err2 := strconv.Atoi(asnStr)
	if err2 != nil {
		log.Fatal(err)
	}

	// Create ASN info
	info := &ASNInfo{
		ASN:     asn,
		Country: fields[3],
		Network: fields[4],
	}

	// Create IP range
	ipRange := ipaddr.NewSequentialRange(startAddr, endAddr)
	prefixBlocks := ipRange.SpanWithPrefixBlocks()
	for _, block := range prefixBlocks {
		t.trie.Put(block, info)
	}

	return nil
}

// LookupIP finds the ASN info for a given IP address
func (t *ASNTrie) LookupIP(ip net.IP) (*ASNInfo, error) {
	// Parse the IP address
	addr, err := ipaddr.NewIPAddressFromNetIP(ip)
	if err != nil {
		return nil, fmt.Errorf("error parsing IP address: %v", err)
	}

	// Look up in trie
	node := t.trie.LongestPrefixMatch(addr)
	if node == nil {
		return nil, fmt.Errorf("no matching ASN record found for IP: %s", addr)
	}
	return nil, nil
}
