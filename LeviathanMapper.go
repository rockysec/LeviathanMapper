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

// Configuración de las APIs
var (
	apiKeySecurityTrails = os.Getenv("SECURITYTRAILS_API_KEY")
	apiKeyShodan         = os.Getenv("SHODAN_API_KEY")
	apiKeyVirusTotal     = os.Getenv("VIRUSTOTAL_API_KEY")
)

// Variables globales
var (
	concurrency    int
	proxyURL       string
	subdomainChan  chan string
	uniqueSubs     = make(map[string]struct{})
	wg             sync.WaitGroup
	mu             sync.Mutex // Mutex para evitar duplicados en el mapa
	httpClient     *http.Client
)

// Configurar un cliente HTTP con soporte para proxies y timeouts
func configureHTTPClient() {
	transport := &http.Transport{}

	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			fmt.Println("Error en el formato del proxy:", err)
			os.Exit(1)
		}

		// Validar si el proxy es alcanzable
		conn, err := net.DialTimeout("tcp", proxy.Host, defaultTimeout)
		if err != nil {
			fmt.Println("Error al conectar con el proxy:", err)
			os.Exit(1)
		}
		conn.Close()

		// Configurar transporte con proxy
		transport.Proxy = http.ProxyURL(proxy)
		fmt.Println("Proxy configurado:", proxyURL)
	}

	httpClient = &http.Client{
		Timeout:   defaultTimeout,
		Transport: transport,
	}
}

// Realizar una solicitud HTTP con reintentos
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

// Función para consultar Crt.sh
func fetchFromCrtSh(domain string) {
	defer wg.Done()
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, _ := http.NewRequest("GET", url, nil)

	resp, err := fetchWithRetries(req)
	if err != nil {
		fmt.Println("Error al consultar Crt.sh:", err)
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

// Función para consultar SecurityTrails
func fetchFromSecurityTrails(domain string) {
	defer wg.Done()
	if apiKeySecurityTrails == "" {
		fmt.Println("SecurityTrails no configurado. Omite resultados.")
		return
	}

	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("apikey", apiKeySecurityTrails)

	resp, err := fetchWithRetries(req)
	if err != nil {
		fmt.Println("Error al consultar SecurityTrails:", err)
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

// Función para consultar Shodan
func fetchFromShodan(domain string) {
	defer wg.Done()
	if apiKeyShodan == "" {
		fmt.Println("Shodan no configurado. Omite resultados.")
		return
	}

	url := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, apiKeyShodan)
	req, _ := http.NewRequest("GET", url, nil)

	resp, err := fetchWithRetries(req)
	if err != nil {
		fmt.Println("Error al consultar Shodan:", err)
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

// Función para consultar VirusTotal
func fetchFromVirusTotal(domain string) {
	defer wg.Done()
	if apiKeyVirusTotal == "" {
		fmt.Println("VirusTotal no configurado. Omite resultados.")
		return
	}

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains", domain)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("x-apikey", apiKeyVirusTotal)

	resp, err := fetchWithRetries(req)
	if err != nil {
		fmt.Println("Error al consultar VirusTotal:", err)
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

// Función para añadir subdominios evitando duplicados
func addSubdomain(subdomain string) {
	mu.Lock() // Mutex para evitar condiciones de carrera
	defer mu.Unlock()

	// Ignorar subdominios que contengan '*'
	if containsWildcard(subdomain) {
		fmt.Println("Ignorando subdominio con wildcard:", subdomain)
		return
	}

	if _, exists := uniqueSubs[subdomain]; !exists {
		uniqueSubs[subdomain] = struct{}{}
		fmt.Println("Subdominio encontrado:", subdomain)
	}
}

// Función para verificar si un subdominio contiene un wildcard '*'
func containsWildcard(subdomain string) bool {
	return len(subdomain) > 0 && subdomain[0] == '*'
}

// Función para imprimir todos los subdominios encontrados
func printAllSubdomains() {
	fmt.Println("\n=== Subdominios únicos encontrados ===")
	for subdomain := range uniqueSubs {
		fmt.Println(subdomain)
	}
	fmt.Println("==============================")
}

func main() {
	domain := flag.String("domain", "", "Dominio a buscar")
	concurrencyFlag := flag.Int("concurrency", defaultConcurrency, "Número de goroutines concurrentes")
	proxyFlag := flag.String("proxy", "", "URL del proxy (opcional)")
	flag.Parse()

	if *domain == "" {
		fmt.Println("Uso: go run main.go -domain example.com")
		return
	}

	concurrency = *concurrencyFlag
	proxyURL = *proxyFlag

	// Configurar el cliente HTTP
	configureHTTPClient()

	subdomainChan = make(chan string, concurrency)

	// Ejecutar búsqueda de subdominios
	wg.Add(4)
	go fetchFromCrtSh(*domain)
	go fetchFromSecurityTrails(*domain)
	go fetchFromShodan(*domain)
	go fetchFromVirusTotal(*domain)

	wg.Wait()
	close(subdomainChan)

	// Imprimir todos los subdominios encontrados
	printAllSubdomains()
}
