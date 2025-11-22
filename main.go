package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

// Payload holds URL and nonce
type Payload struct {
	URL   string `json:"url"`
	Nonce string `json:"nonce"`
}

var AESKey []byte
var allowedHosts []string

func init() {
	var err error
	_ = godotenv.Load()
	key := os.Getenv("AES_KEY")

	if key == "" {
		log.Fatal("AES_KEY env variable required")
	}

	AESKey, err = base64.StdEncoding.DecodeString(key)
	if err != nil || len(AESKey) != 32 {
		log.Fatal("AES_KEY must be a base64-encoded 32-byte key")
	}

	hosts := os.Getenv("ALLOWED_HOSTS")
	if hosts == "" {
		log.Fatal("ALLOWED_HOSTS env variable required (comma-separated)")
	}
	allowedHosts = strings.Split(hosts, ",")
}

// encrypt payload using AES-256-GCM and return URL-safe base64
func encrypt(payload Payload) (string, error) {
	block, err := aes.NewCipher(AESKey)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	cipherText := aesGCM.Seal(nil, nonce, data, nil)
	combined := append(nonce, cipherText...)
	return base64.RawURLEncoding.EncodeToString(combined), nil
}

// decrypt URL-safe base64 encrypted payload
func decrypt(enc string) (Payload, error) {
	data, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return Payload{}, err
	}
	block, err := aes.NewCipher(AESKey)
	if err != nil {
		return Payload{}, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return Payload{}, err
	}
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return Payload{}, err
	}
	nonce := data[:nonceSize]
	cipherText := data[nonceSize:]
	decrypted, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return Payload{}, err
	}
	var payload Payload
	err = json.Unmarshal(decrypted, &payload)
	return payload, err
}

// POST /shorten?url=<url>
func shortenHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received shorten request:", r.URL.RawQuery)
	// Get all query parameters and join them to the url
	url := r.URL.Query().Get("url")
	if url == "" {
		http.Error(w, "missing url", http.StatusBadRequest)
		return
	}

	// Collect other query parameters except "url"
	params := r.URL.Query()
	queryParts := []string{}
	for key, values := range params {
		if key == "url" {
			continue
		}
		for _, value := range values {
			queryParts = append(queryParts, key+"="+value)
		}
	}
	if len(queryParts) > 0 {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		url = url + sep + strings.Join(queryParts, "&")
	}

	log.Println("Url to encrypt:", url)

	payload := Payload{
		URL:   url,
		Nonce: randomNonce(),
	}
	enc, err := encrypt(payload)
	if err != nil {
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}

	var link string
	if r.TLS == nil {
		link = "http://" + r.Host + "/" + enc
	} else {
		link = "https://" + r.Host + "/" + enc
	}

	resp := map[string]string{"link": link}
	w.Header().Set("Content-Type", "application/json")
	if err = json.NewEncoder(w).Encode(resp); err != nil {
		log.Println("Error encoding JSON response:", err)
	}
}

// GET /{encrypted} -> stream content
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Received redirect request:", r.URL.Path)
	enc := strings.TrimPrefix(r.URL.Path, "/")
	if enc == "" {
		http.Error(w, "missing encrypted path", http.StatusBadRequest)
		return
	}
	payload, err := decrypt(enc)
	if err != nil {
		http.Error(w, "invalid link", http.StatusBadRequest)
		return
	}

	// Validate allowed hosts
	hostAllowed := false
	for _, h := range allowedHosts {
		if strings.EqualFold(payload.URL, h) || strings.Contains(payload.URL, h) || h == "*" {
			hostAllowed = true
			break
		}
	}
	if !hostAllowed {
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}

	log.Println("Tunneling request to:", payload.URL)
	req, err := http.NewRequest("GET", payload.URL, nil)
	if err != nil {
		log.Printf("failed to create request: %v\n", err)
		http.Error(w, "failed to create request", http.StatusInternalServerError)
		return
	}

	hopHeaders := map[string]bool{
		"Connection":          true,
		"Proxy Connection":    true,
		"Keep Alive":          true,
		"Proxy Authenticate":  true,
		"Proxy Authorization": true,
		"Te":                  true,
		"Trailers":            true,
		"Transfer Encoding":   true,
		"Upgrade":             true,
	}
	for name, values := range r.Header {
		if hopHeaders[strings.ToLower(name)] {
			continue
		}
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error fetching target URL:", err)
		http.Error(w, "failed to fetch target URL", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	log.Println("Received response with status:", resp.StatusCode)
	w.WriteHeader(resp.StatusCode)
	if _, err = io.Copy(w, resp.Body); err != nil {
		log.Println("Error copying response body:", err)
	}
	log.Println("Finished proxying request to:", payload.URL)
}

// generate random 8-byte nonce as hex string
func randomNonce() string {
	b := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		log.Fatal("failed to generate nonce:", err)
	}

	return base64.RawURLEncoding.EncodeToString(b)
}

func main() {
	// Serve static files from /static
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/shorten", shortenHandler)

	// Root handler: serve index.html if no encrypted path is provided
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// If path is exactly "/", serve static index.html
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "static/index.html")
			return
		}
		// Otherwise, treat as encrypted proxy
		proxyHandler(w, r)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Println("Encrypted proxy running on port", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
