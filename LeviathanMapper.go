package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

const (
	defaultTimeout     = 5 * time.Second
	defaultConcurrency = 20
	retryLimit         = 3
	retryDelay         = 2 * time.Second
)

// API Variables
var (
	apiKeySecurityTrails = os.Getenv("SECURITYTRAILS_API_KEY")
	apiKeyShodan         = os.Getenv("SHODAN_API_KEY")
	apiKeyVirusTotal     = os.Getenv("VIRUSTOTAL_API_KEY")
)

// Global Variables
var (
	concurrency    int
	proxyURL       string
	subdomainChan  chan string
	uniqueSubs     = make(map[string]struct{})
	wg             sync.WaitGroup
	mu             sync.Mutex // Mutex to avoid duplicates in the map
	httpClient     *http.Client
)

// Configure an HTTP client with support for proxies and timeouts
func configureHTTPClient() {
	transport := &http.Transport{}

	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			fmt.Println("Error in proxy format:", err)
			os.Exit(1)
		}

		// Validate if the proxy is reachable
		conn, err := net.DialTimeout("tcp", proxy.Host, defaultTimeout)
		if err != nil {
			fmt.Println("Error connecting to the proxy:", err)
			os.Exit(1)
		}
		conn.Close()

		// Configure transport with proxy
		transport.Proxy = http.ProxyURL(proxy)
		fmt.Println("Proxy configured:", proxyURL)
	}

	httpClient = &http.Client{
		Timeout:   defaultTimeout,
		Transport: transport,
	}
}

// Perform an HTTP request with retries
func fetchWithRetries(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for i := 0; i < retryLimit; i++ {
		resp, err = httpClient.Do(req)
		if err == nil && resp.StatusCode == 200 {
			return resp, nil
		}
		time.Sleep(retryDelay)
	}
	return nil, err
}

// Function to query Crt.sh
func fetchFromCrtSh(domain string) {
	defer wg.Done()
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, _ := http.NewRequest("GET", url, nil)

	resp, err := fetchWithRetries(req)
	if err != nil {
		fmt.Println("Error querying Crt.sh:", err)
		return
	}
	defer resp.Body.Close()

	var results []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&results); err == nil {
		for _, entry := range results {
			if subdomain, ok := entry["name_value"].(string); ok {
				addSubdomain(subdomain)
			}
		}
	}
}

// Function to query SecurityTrails
func fetchFromSecurityTrails(domain string) {
	defer wg.Done()
	if apiKeySecurityTrails == "" {
		fmt.Println("SecurityTrails not configured. Skipping results.")
		return
	}

	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("apikey", apiKeySecurityTrails)

	resp, err := fetchWithRetries(req)
	if err != nil {
		fmt.Println("Error querying SecurityTrails:", err)
		return
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		if subs, found := result["subdomains"].([]interface{}); found {
			for _, sub := range subs {
				addSubdomain(fmt.Sprintf("%s.%s", sub, domain))
			}
		}
	}
}

// Function to query Shodan
func fetchFromShodan(domain string) {
	defer wg.Done()
	if apiKeyShodan == "" {
		fmt.Println("Shodan not configured. Skipping results.")
		return
	}

	url := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, apiKeyShodan)
	req, _ := http.NewRequest("GET", url, nil)

	resp, err := fetchWithRetries(req)
	if err != nil {
		fmt.Println("Error querying Shodan:", err)
		return
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		if subs, found := result["subdomains"].([]interface{}); found {
			for _, sub := range subs {
				addSubdomain(fmt.Sprintf("%s.%s", sub, domain))
			}
		}
	}
}

// Function to query VirusTotal
func fetchFromVirusTotal(domain string) {
	defer wg.Done()
	if apiKeyVirusTotal == "" {
		fmt.Println("VirusTotal not configured. Skipping results.")
		return
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains", domain)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("x-apikey", apiKeyVirusTotal)

	resp, err := fetchWithRetries(req)
	if err != nil {
		fmt.Println("Error querying VirusTotal:", err)
		return
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		if data, found := result["data"].([]interface{}); found {
			for _, entry := range data {
				if subdomain, ok := entry.(string); ok {
					addSubdomain(subdomain)
				}
			}
		}
	}
}

// Function to add subdomains avoiding duplicates
func addSubdomain(subdomain string) {
	mu.Lock() // Mutex to avoid race conditions
	defer mu.Unlock()

	// Ignore subdomains containing '*'
	if containsWildcard(subdomain) {
		fmt.Println("Ignoring subdomain with wildcard:", subdomain)
		return
	}

	if _, exists := uniqueSubs[subdomain]; !exists {
		uniqueSubs[subdomain] = struct{}{}
		fmt.Println("Subdomain found:", subdomain)
	}
}

// Function to check if a subdomain contains a wildcard '*'
func containsWildcard(subdomain string) bool {
	return len(subdomain) > 0 && subdomain[0] == '*'
}

// Function to print all found subdomains
func printAllSubdomains() {
	fmt.Println("\n=== Unique Subdomains Found ===")
	for subdomain := range uniqueSubs {
		fmt.Println(subdomain)
	}
	fmt.Println("==============================")
}

func main() {
	domain := flag.String("domain", "", "Domain to search")
	concurrencyFlag := flag.Int("concurrency", defaultConcurrency, "Number of concurrent goroutines")
	proxyFlag := flag.String("proxy", "", "Proxy URL (optional)")
	flag.Parse()

	if *domain == "" {
		fmt.Println("Usage: go run main.go -domain example.com")
		return
	}

	concurrency = *concurrencyFlag
	proxyURL = *proxyFlag

	// Configure the HTTP client
	configureHTTPClient()

	subdomainChan = make(chan string, concurrency)

	// Execute subdomain search
	wg.Add(4)
	go fetchFromCrtSh(*domain)
	go fetchFromSecurityTrails(*domain)
	go fetchFromShodan(*domain)
	go fetchFromVirusTotal(*domain)

	wg.Wait()
	close(subdomainChan)

	// Print all found subdomains
	printAllSubdomains()
}
