package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	SubjectScansCompleted = "scans.completed"
	SubjectScansResults   = "scans.results"
)

// ScanResult representa resultado de um scan
type ScanResult struct {
	JobID       string    `json:"job_id"`
	ProbeID     string    `json:"probe_id"`
	Status      string    `json:"status"`
	CompletedAt time.Time `json:"completed_at"`
	ReportXML   string    `json:"report_xml,omitempty"` // base64 encoded
	Summary     struct {
		HostsScanned int `json:"hosts_scanned"`
		VulnsHigh    int `json:"vulns_high"`
		VulnsMedium  int `json:"vulns_medium"`
		VulnsLow     int `json:"vulns_low"`
	} `json:"summary"`
}

type WebhookServer struct {
	nc          *nats.Conn
	forwardURL  string // URL externa para encaminhar resultados
}

func main() {
	// Setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "debug" {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	log.Info().Msg("Starting Greenbone Webhook Receiver")

	// Connect to NATS
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}

	natsToken := os.Getenv("NATS_TOKEN")

	opts := []nats.Option{
		nats.Name("greenbone-webhook"),
		nats.ReconnectWait(2 * time.Second),
		nats.MaxReconnects(-1),
	}

	if natsToken != "" {
		opts = append(opts, nats.Token(natsToken))
	}

	nc, err := nats.Connect(natsURL, opts...)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to connect to NATS")
	}
	defer nc.Close()

	log.Info().Str("url", natsURL).Msg("Connected to NATS")

	server := &WebhookServer{
		nc:         nc,
		forwardURL: os.Getenv("FORWARD_URL"), // opcional
	}

	// Setup router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"healthy"}`))
	})

	// Endpoint para receber resultados dos probes
	r.Post("/results", server.handleResults)
	r.Post("/api/v1/results", server.handleResults)

	// Start server
	port := os.Getenv("WEBHOOK_PORT")
	if port == "" {
		port = "8081"
	}

	log.Info().Str("port", port).Msg("Webhook server starting")

	go func() {
		if err := http.ListenAndServe(":"+port, r); err != nil {
			log.Fatal().Err(err).Msg("Server failed")
		}
	}()

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info().Msg("Shutting down webhook receiver")
}

// handleResults processa resultados dos probes
func (s *WebhookServer) handleResults(w http.ResponseWriter, r *http.Request) {
	// Validate probe token
	token := r.Header.Get("Authorization")
	if token == "" {
		// Para MVP, aceita sem token mas loga warning
		log.Warn().Msg("Received result without authorization")
	}

	// Read body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read request body")
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}

	// Parse result
	var result ScanResult
	if err := json.Unmarshal(body, &result); err != nil {
		log.Error().Err(err).Msg("Failed to parse scan result")
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	log.Info().
		Str("job_id", result.JobID).
		Str("probe_id", result.ProbeID).
		Str("status", result.Status).
		Int("vulns_high", result.Summary.VulnsHigh).
		Int("vulns_medium", result.Summary.VulnsMedium).
		Msg("Received scan result")

	// Publish to NATS para orquestrador
	s.nc.Publish(SubjectScansCompleted, body)

	// Publish resultado completo
	s.nc.Publish(SubjectScansResults, body)

	// Forward para sistema externo se configurado
	if s.forwardURL != "" {
		go s.forwardResult(body)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"received"}`))
}

// forwardResult encaminha resultado para sistema externo
func (s *WebhookServer) forwardResult(body []byte) {
	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Post(s.forwardURL, "application/json", 
		io.NopCloser(io.Reader(nil))) // TODO: usar body corretamente
	if err != nil {
		log.Error().Err(err).Str("url", s.forwardURL).Msg("Failed to forward result")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Warn().
			Str("url", s.forwardURL).
			Int("status", resp.StatusCode).
			Msg("Forward target returned error")
	}
}
