package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kaber420/straws-core/pkg/nativeproto"
	"github.com/kaber420/straws-core/pkg/proxy"
)

const hostName = "com.kaber420.straws.core"

func main() {
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	
	f, _ := os.OpenFile("/tmp/straws_debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	log.SetOutput(f)
	log.Printf("--- Straws Engine Started at %v ---", filepath.Base(exePath))
	
	// Smart discovery of certs directory (Absolute)
	absExeDir, _ := filepath.Abs(exeDir)
	// 1. Check if flag was provided
	// 2. Default to adjacent certs
	certsDir := filepath.Join(absExeDir, "certs")
	
	// Smart discovery logic
	if strings.HasSuffix(absExeDir, "/bin") || strings.HasSuffix(absExeDir, "\\bin") {
		// If in bin/, check parent
		parentCerts := filepath.Join(filepath.Dir(absExeDir), "certs")
		if _, err := os.Stat(parentCerts); err == nil {
			certsDir = parentCerts
		}
	} else {
		// Check CWD (helpful for 'go run')
		cwd, _ := os.Getwd()
		cwdCerts := filepath.Join(cwd, "certs")
		if _, err := os.Stat(cwdCerts); err == nil {
			certsDir = cwdCerts
		} else if _, err := os.Stat(certsDir); os.IsNotExist(err) {
			// If not found adjacent or in CWD, check one level up from EXE
			parentCerts := filepath.Join(filepath.Dir(absExeDir), "certs")
			if _, err := os.Stat(parentCerts); err == nil {
				certsDir = parentCerts
			} else {
				// Try one more level up for deep source structures
				grandParentCerts := filepath.Join(filepath.Dir(filepath.Dir(absExeDir)), "certs")
				if _, err := os.Stat(grandParentCerts); err == nil {
					certsDir = grandParentCerts
				}
			}
		}
	}
	
	// Final validation before flag set
	finalCertsDir, _ := filepath.Abs(certsDir)
	log.Printf("Final certsDir discovery: %s", finalCertsDir)

	registerFlag := flag.Bool("register", false, "Register the host in the browser's native messaging manifests")
	portFlag := flag.String("port", "5782", "Port for the proxy server to listen on")
	certsDirFlag := flag.String("certs-dir", certsDir, "Directory containing .crt and .key files for legal domains")
	flag.Parse()

	if *registerFlag {
		if err := register(); err != nil {
			fmt.Printf("Error registering host: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Host registered successfully!")
		return
	}

	log.Printf("Starting engine with certs-dir: %s", *certsDirFlag)
	run(*portFlag, *certsDirFlag, exePath)
}

func register() error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return err
	}

	manifest := map[string]interface{}{
		"name":              hostName,
		"description":       "StrawsCore Proxy Engine",
		"path":              exePath,
		"type":              "stdio",
		"allowed_extensions": []string{
			"straws@kaber420.com", 
			"strawslite@kaber420.com",
		},
	}

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}

	var manifestDir string
	switch runtime.GOOS {
	case "linux":
		home, _ := os.UserHomeDir()
		manifestDir = filepath.Join(home, ".mozilla", "native-messaging-hosts")
	case "darwin":
		home, _ := os.UserHomeDir()
		manifestDir = filepath.Join(home, "Library", "Application Support", "Mozilla", "NativeMessagingHosts")
	case "windows":
		// Windows requires a registry key, which is more complex to do from Go directly without extra libs.
		// For now, we'll suggest manual registration or use a helper.
		return fmt.Errorf("automatic registration on Windows is not yet implemented (requires registry keys)")
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}

	if err := os.MkdirAll(manifestDir, 0755); err != nil {
		return err
	}

	manifestPath := filepath.Join(manifestDir, hostName+".json")
	return os.WriteFile(manifestPath, manifestJSON, 0644)
}

func run(port, certsDir, exePath string) {
	p := &proxy.ProxyServer{
		Addr:          ":" + port,
		CertsDir:      certsDir,
		RecordingPath: filepath.Join(filepath.Dir(exePath), "straws_sessions.db"),
		OnEvent: func(event map[string]interface{}) {
			respJSON, _ := json.Marshal(event)
			nativeproto.WriteMessage(os.Stdout, respJSON)
		},
	}

	go func() {
		log.Printf("Proxy server starting on %s...", p.Addr)
		nativeproto.WriteMessage(os.Stdout, []byte(`{"type": "ready", "message": "Straws Engine is ready"}`))

		if err := p.Start(); err != nil {
			errJSON, _ := json.Marshal(map[string]interface{}{
				"type":    "error",
				"message": "Engine Error: " + err.Error(),
			})
			nativeproto.WriteMessage(os.Stdout, errJSON)
			log.Fatalf("Proxy server error: %v", err)
		}
	}()

	// Read loop for incoming commands from extension
	for {
		payload, err := nativeproto.ReadMessage(os.Stdin)
		if err != nil {
			log.Fatalf("Error reading message: %v", err)
		}
		
		var cmd struct {
			Command string            `json:"command"`
			Enabled bool              `json:"enabled"`
			Rules   []proxy.ProxyRule `json:"rules"`
		}
		if err := json.Unmarshal(payload, &cmd); err == nil {
			switch cmd.Command {
			case "sync_rules":
				p.UpdateRules(cmd.Rules)
			case "set_logging":
				p.LoggingEnabled = cmd.Enabled
				log.Printf("Logging status changed to: %v", p.LoggingEnabled)
			case "set_recording":
				p.RecordingEnabled = cmd.Enabled
				log.Printf("Recording status changed to: %v", p.RecordingEnabled)
			case "get_certs":
				certs := p.GetAvailableCerts()
				log.Printf("Extension requested certs. Found: %d", len(certs))
				resp, _ := json.Marshal(map[string]interface{}{
					"type":  "certs_list",
					"certs": certs,
				})
				nativeproto.WriteMessage(os.Stdout, resp)
			}
		}
	}
}
