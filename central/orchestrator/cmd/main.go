package main

import (
	"encoding/json"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Subjects NATS
const (
	SubjectScansNew       = "scans.new"       // Novos scans da API
	SubjectScansPending   = "scans.pending"   // Jobs aguardando probe
	SubjectScansAssigned  = "scans.assigned"  // Jobs atribuídos
	SubjectScansCompleted = "scans.completed" // Jobs finalizados
	SubjectProbesStatus   = "probes.status"   // Heartbeat dos probes
	SubjectProbesRegister = "probes.register" // Registro de probes
)

// ScanJob representa um job de scan
type ScanJob struct {
	JobID       string    `json:"job_id"`
	Type        string    `json:"type"` // "full" ou "directed"
	Target      string    `json:"target"`
	Ports       []int     `json:"ports,omitempty"`
	ProbeID     string    `json:"probe_id,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	CompletedAt time.Time `json:"completed_at,omitempty"`
}

// ProbeInfo representa informações de um probe
type ProbeInfo struct {
	ProbeID       string    `json:"probe_id"`
	Location      string    `json:"location"`
	Status        string    `json:"status"` // online, offline, busy
	LastHeartbeat time.Time `json:"last_heartbeat"`
	CurrentJob    string    `json:"current_job,omitempty"`
}

// Orchestrator gerencia distribuição de scans
type Orchestrator struct {
	nc     *nats.Conn
	probes map[string]*ProbeInfo
	jobs   map[string]*ScanJob
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

	log.Info().Msg("Starting Greenbone Orchestrator")

	// Connect to NATS
	natsURL := os.Getenv("NATS_URL")
	if natsURL == "" {
		natsURL = "nats://localhost:4222"
	}

	natsToken := os.Getenv("NATS_TOKEN")

	opts := []nats.Option{
		nats.Name("greenbone-orchestrator"),
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

	orch := &Orchestrator{
		nc:     nc,
		probes: make(map[string]*ProbeInfo),
		jobs:   make(map[string]*ScanJob),
	}

	// Subscribe to new scans
	_, err = nc.Subscribe(SubjectScansNew, orch.handleNewScan)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to subscribe to scans.new")
	}

	// Subscribe to probe registrations
	_, err = nc.Subscribe(SubjectProbesRegister, orch.handleProbeRegister)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to subscribe to probes.register")
	}

	// Subscribe to probe heartbeats
	_, err = nc.Subscribe(SubjectProbesStatus, orch.handleProbeStatus)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to subscribe to probes.status")
	}

	// Subscribe to completed scans
	_, err = nc.Subscribe(SubjectScansCompleted, orch.handleScanCompleted)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to subscribe to scans.completed")
	}

	log.Info().Msg("Orchestrator ready, waiting for jobs...")

	// Wait for shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Info().Msg("Shutting down orchestrator")
}

// handleNewScan processa novos scans vindos da API
func (o *Orchestrator) handleNewScan(msg *nats.Msg) {
	var job ScanJob
	if err := json.Unmarshal(msg.Data, &job); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal scan job")
		return
	}

	// Assign UUID if not present
	if job.JobID == "" {
		job.JobID = uuid.New().String()
	}
	job.Status = "pending"
	job.CreatedAt = time.Now()

	log.Info().
		Str("job_id", job.JobID).
		Str("type", job.Type).
		Str("target", job.Target).
		Msg("Received new scan job")

	// Store job
	o.jobs[job.JobID] = &job

	// Find available probe
	probe := o.findAvailableProbe()
	if probe == nil {
		log.Warn().Str("job_id", job.JobID).Msg("No available probe, job queued")
		// Publish to pending queue
		data, _ := json.Marshal(job)
		o.nc.Publish(SubjectScansPending, data)
		return
	}

	// Assign to probe
	job.ProbeID = probe.ProbeID
	job.Status = "assigned"
	probe.Status = "busy"
	probe.CurrentJob = job.JobID

	log.Info().
		Str("job_id", job.JobID).
		Str("probe_id", probe.ProbeID).
		Msg("Assigned job to probe")

	// Publish to probe-specific queue
	data, _ := json.Marshal(job)
	o.nc.Publish("probes."+probe.ProbeID+".jobs", data)

	// Also publish assignment notification
	o.nc.Publish(SubjectScansAssigned, data)
}

// handleProbeRegister processa registro de novos probes
func (o *Orchestrator) handleProbeRegister(msg *nats.Msg) {
	var probe ProbeInfo
	if err := json.Unmarshal(msg.Data, &probe); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal probe registration")
		return
	}

	probe.Status = "online"
	probe.LastHeartbeat = time.Now()
	o.probes[probe.ProbeID] = &probe

	log.Info().
		Str("probe_id", probe.ProbeID).
		Str("location", probe.Location).
		Msg("Probe registered")

	// Reply with confirmation
	if msg.Reply != "" {
		msg.Respond([]byte(`{"status":"registered"}`))
	}
}

// handleProbeStatus processa heartbeats dos probes
func (o *Orchestrator) handleProbeStatus(msg *nats.Msg) {
	var status struct {
		ProbeID string `json:"probe_id"`
		Status  string `json:"status"`
	}

	if err := json.Unmarshal(msg.Data, &status); err != nil {
		return
	}

	if probe, ok := o.probes[status.ProbeID]; ok {
		probe.LastHeartbeat = time.Now()
		probe.Status = status.Status
	}
}

// handleScanCompleted processa scans finalizados
func (o *Orchestrator) handleScanCompleted(msg *nats.Msg) {
	var result struct {
		JobID   string `json:"job_id"`
		ProbeID string `json:"probe_id"`
		Status  string `json:"status"`
	}

	if err := json.Unmarshal(msg.Data, &result); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal completion")
		return
	}

	log.Info().
		Str("job_id", result.JobID).
		Str("probe_id", result.ProbeID).
		Str("status", result.Status).
		Msg("Scan completed")

	// Update job status
	if job, ok := o.jobs[result.JobID]; ok {
		job.Status = result.Status
		job.CompletedAt = time.Now()
	}

	// Mark probe as available
	if probe, ok := o.probes[result.ProbeID]; ok {
		probe.Status = "online"
		probe.CurrentJob = ""
	}
}

// findAvailableProbe encontra um probe disponível
func (o *Orchestrator) findAvailableProbe() *ProbeInfo {
	for _, probe := range o.probes {
		if probe.Status == "online" {
			return probe
		}
	}
	return nil
}
