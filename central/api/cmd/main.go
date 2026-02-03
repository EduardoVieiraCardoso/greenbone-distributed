package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// NATS subjects
const (
	SubjectScansNew = "scans.new"
)

// ScanRequest representa uma requisição de scan
type ScanRequest struct {
	Type   string `json:"type"`   // "full" ou "directed"
	Target string `json:"target"` // IP, range ou hostname
	Ports  []int  `json:"ports,omitempty"`
}

// ScanResponse resposta ao criar scan
type ScanResponse struct {
	JobID     string    `json:"job_id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// APIServer servidor da API
type APIServer struct {
	nc       *nats.Conn
	apiToken string
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

	log.Info().Msg("Starting Greenbone API")

	// Connect to NATS
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}

	natsToken := os.Getenv("NATS_TOKEN")

	opts := []nats.Option{
		nats.Name("greenbone-api"),
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

	apiToken := os.Getenv("API_TOKEN")
	if apiToken == "" {
		log.Warn().Msg("API_TOKEN not set, authentication disabled")
	}

	server := &APIServer{
		nc:       nc,
		apiToken: apiToken,
	}

	// Setup router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	// Routes
	r.Get("/health", server.handleHealth)

	r.Route("/api/v1", func(r chi.Router) {
		// Auth middleware
		if apiToken != "" {
			r.Use(server.authMiddleware)
		}

		r.Post("/scans", server.handleCreateScan)
		r.Get("/scans/{jobID}", server.handleGetScan)
		r.Get("/probes", server.handleListProbes)
	})

	// Start server
	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8080"
	}

	log.Info().Str("port", port).Msg("API server starting")

	go func() {
		if err := http.ListenAndServe(":"+port, r); err != nil {
			log.Fatal().Err(err).Msg("Server failed")
		}
	}()

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info().Msg("Shutting down API")
}

// authMiddleware valida token de API
func (s *APIServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		// Expect: Bearer <token>
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		if token != s.apiToken {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// handleHealth endpoint de saúde
func (s *APIServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"healthy"}`))
}

// handleCreateScan cria novo scan
func (s *APIServer) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Validate
	if req.Target == "" {
		http.Error(w, `{"error":"target is required"}`, http.StatusBadRequest)
		return
	}

	if req.Type == "" {
		req.Type = "full"
	}

	if req.Type != "full" && req.Type != "directed" {
		http.Error(w, `{"error":"type must be 'full' or 'directed'"}`, http.StatusBadRequest)
		return
	}

	if req.Type == "directed" && len(req.Ports) == 0 {
		http.Error(w, `{"error":"ports required for directed scan"}`, http.StatusBadRequest)
		return
	}

	// Create job
	job := struct {
		JobID     string    `json:"job_id"`
		Type      string    `json:"type"`
		Target    string    `json:"target"`
		Ports     []int     `json:"ports,omitempty"`
		Status    string    `json:"status"`
		CreatedAt time.Time `json:"created_at"`
	}{
		JobID:     uuid.New().String(),
		Type:      req.Type,
		Target:    req.Target,
		Ports:     req.Ports,
		Status:    "pending",
		CreatedAt: time.Now(),
	}

	// Publish to NATS
	data, _ := json.Marshal(job)
	if err := s.nc.Publish(SubjectScansNew, data); err != nil {
		log.Error().Err(err).Msg("Failed to publish scan job")
		http.Error(w, `{"error":"failed to queue scan"}`, http.StatusInternalServerError)
		return
	}

	log.Info().
		Str("job_id", job.JobID).
		Str("type", job.Type).
		Str("target", job.Target).
		Msg("Scan job created")

	// Respond
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ScanResponse{
		JobID:     job.JobID,
		Status:    job.Status,
		CreatedAt: job.CreatedAt,
	})
}

// handleGetScan obtém status de um scan
func (s *APIServer) handleGetScan(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobID")

	// TODO: implementar lookup real via NATS request/reply
	// Por enquanto, retorna placeholder
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"job_id": jobID,
		"status": "unknown",
		"note":   "status lookup not yet implemented",
	})
}

// handleListProbes lista probes disponíveis
func (s *APIServer) handleListProbes(w http.ResponseWriter, r *http.Request) {
	// TODO: implementar via NATS request/reply ao orchestrator
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"probes": []interface{}{},
		"note":   "probe listing not yet implemented",
	})
}
