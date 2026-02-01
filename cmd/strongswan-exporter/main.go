package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/strongswan/govici/vici"
)

const (
	defaultListenAddr  = ":9814"
	defaultMetricsPath = "/metrics"
	defaultViciSocket  = "/var/run/charon.vici"
	defaultTimeout     = 5 * time.Second
	defaultEventBuffer = 128
)

type eventKey struct {
	user string
	conn string
}

type eventState struct {
	lastUp      time.Time
	lastDown    time.Time
	connects    uint64
	disconnects uint64
}

type eventStore struct {
	mu          sync.RWMutex
	states      map[eventKey]*eventState
	lastUp      *prometheus.Desc
	lastDown    *prometheus.Desc
	connects    *prometheus.Desc
	disconnects *prometheus.Desc
}

func newEventStore() *eventStore {
	return &eventStore{
		states: make(map[eventKey]*eventState),
		lastUp: prometheus.NewDesc(
			"strongswan_user_last_connect_at_seconds",
			"Unix timestamp of the last IKE_SA up event for a user (from VICI ike-updown).",
			[]string{"user", "conn"},
			nil,
		),
		lastDown: prometheus.NewDesc(
			"strongswan_user_last_disconnect_at_seconds",
			"Unix timestamp of the last IKE_SA down event for a user (from VICI ike-updown).",
			[]string{"user", "conn"},
			nil,
		),
		connects: prometheus.NewDesc(
			"strongswan_user_connects_total",
			"Total number of IKE_SA up events for a user (from VICI ike-updown).",
			[]string{"user", "conn"},
			nil,
		),
		disconnects: prometheus.NewDesc(
			"strongswan_user_disconnects_total",
			"Total number of IKE_SA down events for a user (from VICI ike-updown).",
			[]string{"user", "conn"},
			nil,
		),
	}
}

func (s *eventStore) Describe(ch chan<- *prometheus.Desc) {
	ch <- s.lastUp
	ch <- s.lastDown
	ch <- s.connects
	ch <- s.disconnects
}

func (s *eventStore) Collect(ch chan<- prometheus.Metric) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for key, state := range s.states {
		if !state.lastUp.IsZero() {
			ch <- prometheus.MustNewConstMetric(
				s.lastUp,
				prometheus.GaugeValue,
				float64(state.lastUp.Unix()),
				key.user,
				key.conn,
			)
		}
		if !state.lastDown.IsZero() {
			ch <- prometheus.MustNewConstMetric(
				s.lastDown,
				prometheus.GaugeValue,
				float64(state.lastDown.Unix()),
				key.user,
				key.conn,
			)
		}
		ch <- prometheus.MustNewConstMetric(
			s.connects,
			prometheus.CounterValue,
			float64(state.connects),
			key.user,
			key.conn,
		)
		ch <- prometheus.MustNewConstMetric(
			s.disconnects,
			prometheus.CounterValue,
			float64(state.disconnects),
			key.user,
			key.conn,
		)
	}
}

func (s *eventStore) handleIKEUpdown(ts time.Time, msg *vici.Message) {
	up := msgBool(msg, "up")
	for _, key := range msg.Keys() {
		if key == "up" {
			continue
		}
		value := msg.Get(key)
		saMsg, ok := value.(*vici.Message)
		if !ok {
			continue
		}
		conn := msgString(saMsg, "name")
		if conn == "" {
			conn = key
		}
		user := firstNonEmpty(msgString(saMsg, "remote-eap-id"), msgString(saMsg, "remote-id"))
		if user == "" {
			user = "unknown"
		}
		s.update(ts, user, conn, up)
	}
}

func (s *eventStore) update(ts time.Time, user, conn string, up bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := eventKey{user: user, conn: conn}
	state, ok := s.states[key]
	if !ok {
		state = &eventState{}
		s.states[key] = state
	}
	if up {
		state.lastUp = ts
		state.connects++
		return
	}
	state.lastDown = ts
	state.disconnects++
}

type exporter struct {
	socket        string
	scrapeTimeout time.Duration
	logger        *log.Logger
	mu            sync.Mutex
	events        *eventStore

	upDesc               *prometheus.Desc
	userConnectedDesc    *prometheus.Desc
	userConnectedAtDesc  *prometheus.Desc
	childBytesInDesc     *prometheus.Desc
	childBytesOutDesc    *prometheus.Desc
	childPacketsInDesc   *prometheus.Desc
	childPacketsOutDesc  *prometheus.Desc
	childInstalledAtDesc *prometheus.Desc
}

func newExporter(socket string, timeout time.Duration, logger *log.Logger, events *eventStore) *exporter {
	return &exporter{
		socket:        socket,
		scrapeTimeout: timeout,
		logger:        logger,
		events:        events,
		upDesc: prometheus.NewDesc(
			"strongswan_up",
			"Whether the exporter could successfully query VICI list-sas.",
			nil,
			nil,
		),
		userConnectedDesc: prometheus.NewDesc(
			"strongswan_user_connected",
			"Whether a user currently has an established IKE_SA with at least one INSTALLED CHILD_SA.",
			[]string{"user", "conn", "remote_addr"},
			nil,
		),
		userConnectedAtDesc: prometheus.NewDesc(
			"strongswan_user_connected_at_seconds",
			"Unix timestamp when the current IKE_SA was established (from list-sas established).",
			[]string{"user", "conn", "remote_addr"},
			nil,
		),
		childBytesInDesc: prometheus.NewDesc(
			"strongswan_child_bytes_in_total",
			"Bytes received by an INSTALLED CHILD_SA (from list-sas bytes-in).",
			[]string{"user", "conn", "child", "child_id", "remote_addr"},
			nil,
		),
		childBytesOutDesc: prometheus.NewDesc(
			"strongswan_child_bytes_out_total",
			"Bytes sent by an INSTALLED CHILD_SA (from list-sas bytes-out).",
			[]string{"user", "conn", "child", "child_id", "remote_addr"},
			nil,
		),
		childPacketsInDesc: prometheus.NewDesc(
			"strongswan_child_packets_in_total",
			"Packets received by an INSTALLED CHILD_SA (from list-sas packets-in).",
			[]string{"user", "conn", "child", "child_id", "remote_addr"},
			nil,
		),
		childPacketsOutDesc: prometheus.NewDesc(
			"strongswan_child_packets_out_total",
			"Packets sent by an INSTALLED CHILD_SA (from list-sas packets-out).",
			[]string{"user", "conn", "child", "child_id", "remote_addr"},
			nil,
		),
		childInstalledAtDesc: prometheus.NewDesc(
			"strongswan_child_installed_at_seconds",
			"Unix timestamp when the CHILD_SA was installed (from list-sas install-time).",
			[]string{"user", "conn", "child", "child_id", "remote_addr"},
			nil,
		),
	}
}

func (e *exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- e.upDesc
	ch <- e.userConnectedDesc
	ch <- e.userConnectedAtDesc
	ch <- e.childBytesInDesc
	ch <- e.childBytesOutDesc
	ch <- e.childPacketsInDesc
	ch <- e.childPacketsOutDesc
	ch <- e.childInstalledAtDesc
	e.events.Describe(ch)
}

func (e *exporter) Collect(ch chan<- prometheus.Metric) {
	e.mu.Lock()
	defer e.mu.Unlock()

	up := 1.0
	ctx, cancel := context.WithTimeout(context.Background(), e.scrapeTimeout)
	defer cancel()

	session, err := vici.NewSession(vici.WithSocketPath(e.socket))
	if err != nil {
		e.logger.Printf("vici session error: %v", err)
		up = 0
		ch <- prometheus.MustNewConstMetric(e.upDesc, prometheus.GaugeValue, up)
		e.events.Collect(ch)
		return
	}
	defer session.Close()

	seq := session.CallStreaming(ctx, "list-sas", "list-sa", nil)
	now := time.Now()
	for msg, err := range seq {
		if err != nil {
			up = 0
			e.logger.Printf("list-sas error: %v", err)
			break
		}
		if msg == nil {
			continue
		}
		if msgErr := msg.Err(); msgErr != nil {
			up = 0
			e.logger.Printf("list-sas message error: %v", msgErr)
			break
		}
		e.collectListSAs(ch, now, msg)
	}

	ch <- prometheus.MustNewConstMetric(e.upDesc, prometheus.GaugeValue, up)
	e.events.Collect(ch)
}

func (e *exporter) collectListSAs(ch chan<- prometheus.Metric, now time.Time, msg *vici.Message) {
	for _, key := range msg.Keys() {
		value := msg.Get(key)
		saMsg, ok := value.(*vici.Message)
		if !ok {
			continue
		}
		conn := msgString(saMsg, "name")
		if conn == "" {
			conn = key
		}
		user := firstNonEmpty(msgString(saMsg, "remote-eap-id"), msgString(saMsg, "remote-id"))
		if user == "" {
			user = "unknown"
		}
		remoteAddr := msgString(saMsg, "remote-host")

		childSAs := msgMessage(saMsg, "child-sas")
		if childSAs == nil {
			continue
		}
		hasInstalledChild := false
		for _, childKey := range childSAs.Keys() {
			childValue := childSAs.Get(childKey)
			childMsg, ok := childValue.(*vici.Message)
			if !ok {
				continue
			}
			if !strings.EqualFold(msgString(childMsg, "state"), "INSTALLED") {
				continue
			}
			hasInstalledChild = true
			childName := msgString(childMsg, "name")
			if childName == "" {
				childName = childKey
			}
			bytesIn := msgUint(childMsg, "bytes-in")
			bytesOut := msgUint(childMsg, "bytes-out")
			packetsIn := msgUint(childMsg, "packets-in")
			packetsOut := msgUint(childMsg, "packets-out")
			installTime := msgUint(childMsg, "install-time")

			ch <- prometheus.MustNewConstMetric(
				e.childBytesInDesc,
				prometheus.CounterValue,
				float64(bytesIn),
				user,
				conn,
				childName,
				childKey,
				remoteAddr,
			)
			ch <- prometheus.MustNewConstMetric(
				e.childBytesOutDesc,
				prometheus.CounterValue,
				float64(bytesOut),
				user,
				conn,
				childName,
				childKey,
				remoteAddr,
			)
			ch <- prometheus.MustNewConstMetric(
				e.childPacketsInDesc,
				prometheus.CounterValue,
				float64(packetsIn),
				user,
				conn,
				childName,
				childKey,
				remoteAddr,
			)
			ch <- prometheus.MustNewConstMetric(
				e.childPacketsOutDesc,
				prometheus.CounterValue,
				float64(packetsOut),
				user,
				conn,
				childName,
				childKey,
				remoteAddr,
			)
			if installTime > 0 {
				installedAt := now.Add(-time.Duration(installTime) * time.Second).Unix()
				ch <- prometheus.MustNewConstMetric(
					e.childInstalledAtDesc,
					prometheus.GaugeValue,
					float64(installedAt),
					user,
					conn,
					childName,
					childKey,
					remoteAddr,
				)
			}
		}

		if hasInstalledChild {
			established := msgUint(saMsg, "established")
			if established > 0 {
				connectedAt := now.Add(-time.Duration(established) * time.Second).Unix()
				ch <- prometheus.MustNewConstMetric(
					e.userConnectedAtDesc,
					prometheus.GaugeValue,
					float64(connectedAt),
					user,
					conn,
					remoteAddr,
				)
			}
			ch <- prometheus.MustNewConstMetric(
				e.userConnectedDesc,
				prometheus.GaugeValue,
				1,
				user,
				conn,
				remoteAddr,
			)
		}
	}
}

func msgString(msg *vici.Message, key string) string {
	if msg == nil {
		return ""
	}
	value := msg.Get(key)
	switch typed := value.(type) {
	case string:
		return typed
	case []string:
		if len(typed) > 0 {
			return typed[0]
		}
	}
	return ""
}

func msgMessage(msg *vici.Message, key string) *vici.Message {
	if msg == nil {
		return nil
	}
	value := msg.Get(key)
	childMsg, ok := value.(*vici.Message)
	if !ok {
		return nil
	}
	return childMsg
}

func msgUint(msg *vici.Message, key string) uint64 {
	value := msgString(msg, key)
	if value == "" {
		return 0
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0
	}
	return parsed
}

func msgBool(msg *vici.Message, key string) bool {
	value := strings.ToLower(strings.TrimSpace(msgString(msg, key)))
	switch value {
	case "yes", "true", "1", "up":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func startEventListener(ctx context.Context, socket string, buffer int, store *eventStore, logger *log.Logger) {
	go func() {
		backoff := time.Second
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			session, err := vici.NewSession(vici.WithSocketPath(socket))
			if err != nil {
				logger.Printf("vici event session error: %v", err)
				sleepWithContext(ctx, backoff)
				backoff = nextBackoff(backoff)
				continue
			}

			events := make(chan vici.Event, buffer)
			session.NotifyEvents(events)
			if err := session.Subscribe("ike-updown"); err != nil {
				logger.Printf("vici subscribe error: %v", err)
				session.Close()
				sleepWithContext(ctx, backoff)
				backoff = nextBackoff(backoff)
				continue
			}
			backoff = time.Second

			for {
				select {
				case <-ctx.Done():
					session.Close()
					return
				case ev, ok := <-events:
					if !ok {
						session.Close()
						sleepWithContext(ctx, backoff)
						backoff = nextBackoff(backoff)
						goto reconnect
					}
					if ev.Name == "ike-updown" {
						store.handleIKEUpdown(ev.Timestamp, ev.Message)
					}
				}
			}
		reconnect:
			continue
		}
	}()
}

func nextBackoff(current time.Duration) time.Duration {
	if current >= 30*time.Second {
		return 30 * time.Second
	}
	return current * 2
}

func sleepWithContext(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func main() {
	listenAddr := flag.String("listen", defaultListenAddr, "HTTP listen address.")
	metricsPath := flag.String("metrics-path", defaultMetricsPath, "HTTP path for Prometheus metrics.")
	viciSocket := flag.String("vici-socket", defaultViciSocket, "Path to the charon.vici socket.")
	scrapeTimeout := flag.Duration("scrape-timeout", defaultTimeout, "Timeout for VICI list-sas calls.")
	eventBuffer := flag.Int("event-buffer", defaultEventBuffer, "Event channel buffer size for VICI subscriptions.")
	flag.Parse()

	logger := log.New(os.Stdout, "strongswan-exporter: ", log.LstdFlags)

	events := newEventStore()
	exporter := newExporter(*viciSocket, *scrapeTimeout, logger, events)
	registry := prometheus.NewRegistry()
	registry.MustRegister(exporter)
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	registry.MustRegister(prometheus.NewGoCollector())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startEventListener(ctx, *viciSocket, *eventBuffer, events, logger)

	mux := http.NewServeMux()
	mux.Handle(*metricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/-/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Printf("http shutdown error: %v", err)
		}
	}()

	logger.Printf("listening on %s%s (vici socket %s)", *listenAddr, *metricsPath, *viciSocket)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Printf("http server error: %v", err)
		os.Exit(1)
	}
}
