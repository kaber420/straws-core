package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from careldpos! You are connected via HTTPS.")
		log.Printf("Received request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	})

	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)

	certFlag := flag.String("cert", filepath.Join(exeDir, "certs", "careldpos.crt"), "Path to certificate file")
	keyFlag := flag.String("key", filepath.Join(exeDir, "certs", "careldpos.key"), "Path to key file")
	addrFlag := flag.String("addr", ":8100", "Address to listen on")
	flag.Parse()

	log.Printf("Starting test server on %s with cert %s", *addrFlag, *certFlag)
	err := http.ListenAndServeTLS(*addrFlag, *certFlag, *keyFlag, mux)
	if err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
