package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
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
	apiKeyCensys         = os.Getenv("CENSYS_API_KEY")
	apiKeyShodan         = os.Getenv("SHODAN_API_KEY")
	apiKeyAmass          = os.Getenv("AMASS_API_KEY")
)

// Variables globales
var (
	concurrency   int
	proxyURL      string
	subdomainChan = make(chan string, defaultConcurrency)
	uniqueSubs    = make(map[string]struct{})
	wg            sync.WaitGroup
	mu            sync.Mutex // Mutex para evitar duplicados en el mapa
)

// Configurar un cliente HTTP con soporte para proxies y reintentos
func getHTTPClient() *http.Client {
	client := &http.Client{Timeout: defaultTimeout}
	return client
}

// Realizar una solicitud HTTP con reintentos
func fetchWithRetries(req *http.Request) (*http.Response, error) {
	client := getHTTPClient()
	var resp *http.Response
	var err error

	for i := 0; i < retryLimit; i++ {
		resp, err = client.Do(req)
		if err == nil && resp.StatusCode == 200 {
			return resp, nil
		}
		time.Sleep(retryDelay)
	}
	return nil, err
}

// Función para consultar Amass
func fetchFromAmass(domain string) {
	defer wg.Done()
	if apiKeyAmass == "" {
		fmt.Println("Amass no configurado. Omite resultados.")
		return
	}

	url := fmt.Sprintf("https://api.amass.io/v1/subdomains/%s?apikey=%s", domain, apiKeyAmass)
	req, _ := http.NewRequest("GET", url, nil)

	resp, err := fetchWithRetries(req)
	if err != nil {
		fmt.Println("Error al consultar Amass:", err)
		return
	}
	defer resp.Body.Close()

	var result []string
	if err := json.NewDecoder(resp.Body).Decode(&result); err == nil {
		for _, sub := range result {
			addSubdomain(sub)
		}
	}
}

// Función para consultar Crt.sh
func fetchFromCrtSh(domain string) {
	defer wg.Done()
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	resp, err := http.Get(url)
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

// Función para añadir subdominios evitando duplicados
func addSubdomain(subdomain string) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := uniqueSubs[subdomain]; !exists {
		uniqueSubs[subdomain] = struct{}{}
		fmt.Println("Subdominio encontrado:", subdomain)
	}
}

// Función para imprimir todos los subdominios encontrados
func printAllSubdomains() {
	fmt.Println("\n=== Subdominios encontrados ===")
	for subdomain := range uniqueSubs {
		fmt.Println(subdomain)
	}
	fmt.Println("==============================")
}

// Función concurrente para procesar subdominios
func processSubdomains() {
	for subdomain := range subdomainChan {
		if validateSubdomain(subdomain) {
			fmt.Println("Subdominio activo:", subdomain)
		}
	}
}

// Validar si un subdominio está activo
func validateSubdomain(subdomain string) bool {
	_, err := net.LookupHost(subdomain)
	return err == nil
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

	// Iniciar búsqueda de subdominios
	wg.Add(1)
	go fetchFromCrtSh(*domain)

	// Consultar APIs solo si están configuradas
	wg.Add(3)
	go fetchFromSecurityTrails(*domain)
	go fetchFromShodan(*domain)
	go fetchFromAmass(*domain)

	wg.Wait()
	close(subdomainChan)

	// Imprimir todos los subdominios encontrados
	printAllSubdomains()
}
