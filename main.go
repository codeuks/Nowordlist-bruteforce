package main

import (
	"flag"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	Host string
	Port int
	Open bool
}

type Scanner struct {
	timeout time.Duration
	threads int
}

func NewScanner(timeout time.Duration, threads int) *Scanner {
	return &Scanner{
		timeout: timeout,
		threads: threads,
	}
}

// TCP port tarama fonksiyonu
func (s *Scanner) scanPort(host string, port int, results chan<- ScanResult) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	
	result := ScanResult{
		Host: host,
		Port: port,
		Open: err == nil,
	}
	
	if conn != nil {
		conn.Close()
	}
	
	results <- result
}

// Port aralığını parse etme
func parsePortRange(portRange string) ([]int, error) {
	var ports []int
	
	if strings.Contains(portRange, "-") {
		parts := strings.Split(portRange, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid port range format")
		}
		
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, err
		}
		
		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, err
		}
		
		for i := start; i <= end; i++ {
			ports = append(ports, i)
		}
	} else if strings.Contains(portRange, ",") {
		portStrs := strings.Split(portRange, ",")
		for _, portStr := range portStrs {
			port, err := strconv.Atoi(strings.TrimSpace(portStr))
			if err != nil {
				return nil, err
			}
			ports = append(ports, port)
		}
	} else {
		port, err := strconv.Atoi(portRange)
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	
	return ports, nil
}

// Ana tarama fonksiyonu
func (s *Scanner) ScanPorts(host string, ports []int) []ScanResult {
	results := make(chan ScanResult, len(ports))
	var wg sync.WaitGroup
	
	// Thread limiti için semaphore
	semaphore := make(chan struct{}, s.threads)
	
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{} // Thread slot al
			s.scanPort(host, p, results)
			<-semaphore // Thread slot bırak
		}(port)
	}
	
	wg.Wait()
	close(results)
	
	var scanResults []ScanResult
	for result := range results {
		scanResults = append(scanResults, result)
	}
	
	return scanResults
}

// Host keşfi (ping benzeri)
func (s *Scanner) isHostAlive(host string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", host), time.Second*2)
	if err == nil {
		conn.Close()
		return true
	}
	
	// HTTP portu açık değilse 22 (SSH) deneyelim
	conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:22", host), time.Second*2)
	if err == nil {
		conn.Close()
		return true
	}
	
	return false
}

// Sonuçları yazdırma
func printResults(results []ScanResult, showClosed bool) {
	// Port numarasına göre sırala
	sort.Slice(results, func(i, j int) bool {
		return results[i].Port < results[j].Port
	})
	
	fmt.Printf("\nScan Results for %s:\n", results[0].Host)
	fmt.Println("PORT\tSTATE")
	fmt.Println("----\t-----")
	
	openPorts := 0
	for _, result := range results {
		if result.Open {
			fmt.Printf("%d/tcp\topen\n", result.Port)
			openPorts++
		} else if showClosed {
			fmt.Printf("%d/tcp\tclosed\n", result.Port)
		}
	}
	
	fmt.Printf("\nScan completed: %d open ports found\n", openPorts)
}

func main() {
	var (
		host        = flag.String("host", "", "Target host to scan")
		portRange   = flag.String("ports", "1-1000", "Port range to scan (e.g., 1-1000, 22,80,443)")
		threads     = flag.Int("threads", 100, "Number of concurrent threads")
		timeout     = flag.Duration("timeout", time.Second*2, "Connection timeout")
		showClosed  = flag.Bool("show-closed", false, "Show closed ports")
		hostDiscovery = flag.Bool("host-discovery", false, "Perform host discovery")
	)
	
	flag.Parse()
	
	if *host == "" {
		fmt.Println("Usage: go run main.go -host <target_host> [options]")
		flag.PrintDefaults()
		return
	}
	
	scanner := NewScanner(*timeout, *threads)
	
	// Host keşfi
	if *hostDiscovery {
		fmt.Printf("Performing host discovery for %s...\n", *host)
		if scanner.isHostAlive(*host) {
			fmt.Printf("Host %s is up\n", *host)
		} else {
			fmt.Printf("Host %s appears to be down\n", *host)
			return
		}
	}
	
	// Port tarama
	ports, err := parsePortRange(*portRange)
	if err != nil {
		fmt.Printf("Error parsing port range: %v\n", err)
		return
	}
	
	fmt.Printf("Starting port scan on %s...\n", *host)
	fmt.Printf("Scanning %d ports with %d threads\n", len(ports), *threads)
	
	startTime := time.Now()
	results := scanner.ScanPorts(*host, ports)
	duration := time.Since(startTime)
	
	printResults(results, *showClosed)
	fmt.Printf("Scan completed in %v\n", duration)
}