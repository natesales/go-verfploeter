package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"gopkg.in/yaml.v3"
)

var (
	configFile  = flag.String("c", "config.yml", "Config file")
	targetsFile = flag.String("t", "targets.txt", "Targets file")
	verbose     = flag.Bool("v", false, "Enable verbose logging")

	version = "dev" // Set by linker
	pc4     *icmp.PacketConn
	pc6     *icmp.PacketConn

	// Metrics
	requests prometheus.Counter
	replies  *prometheus.CounterVec
)

type Config struct {
	ID     uint8  `yaml:"id"`
	Listen string `yaml:"listen"`
	Probe  struct {
		Interval time.Duration `yaml:"interval"`
		Source4  string        `yaml:"source4"`
		Source6  string        `yaml:"source6"`
	} `yaml:"probe"`
	Nodes map[uint8]string `yaml:"nodes"`
}

func findNode(id uint8, nodes map[uint8]string) string {
	if node, ok := nodes[id]; ok {
		return node
	}
	return fmt.Sprintf("unknown (id %d)", id)
}

// icmpProbe sends an ICMP packet to a given target with an ID
func icmpProbe(target string, id int) error {
	targetIP, err := net.ResolveIPAddr("ip", target)
	if err != nil {
		return err
	}

	// Create the ICMP message
	icmpMessage := icmp.Message{
		Code: 0,
		Body: &icmp.Echo{ID: id},
	}
	if targetIP.IP.To4() != nil {
		icmpMessage.Type = ipv4.ICMPTypeEcho
	} else {
		icmpMessage.Type = ipv6.ICMPTypeEchoRequest
	}

	bytes, err := icmpMessage.Marshal(nil)
	if err != nil {
		return err
	}

	// Send the packet
	if targetIP.IP.To4() != nil {
		_, err = pc4.WriteTo(bytes, targetIP)
	} else {
		_, err = pc6.WriteTo(bytes, targetIP)
	}
	return err
}

// readEchoReply reads and parses an ICMP message from an icmp.PacketConn
func readEchoReply(pc *icmp.PacketConn, nodes map[uint8]string) (*icmp.Echo, net.Addr, error) {
	reply := make([]byte, 1500)
	n, src, err := pc.ReadFrom(reply)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read from icmp.PacketConn: %s", err)
	}

	var proto int
	if ip := net.ParseIP(pc.LocalAddr().String()); ip.To4() != nil {
		proto = 1 // ICMP
	} else {
		proto = 58 // ICMPv6
	}

	icmpMessage, err := icmp.ParseMessage(proto, reply[:n])
	if err != nil {
		return nil, nil, fmt.Errorf("unable to parse ICMP message: %s", err)
	}

	if icmpMessage.Type != ipv4.ICMPTypeEchoReply && icmpMessage.Type != ipv6.ICMPTypeEchoReply {
		return nil, nil, fmt.Errorf("unexpected ICMP message type %s", icmpMessage.Type)
	}

	body, ok := icmpMessage.Body.(*icmp.Echo)
	if !ok {
		return nil, nil, fmt.Errorf("unable to assert message body as *icmp.Echo (this should never happen): %+v", icmpMessage.Body)
	}
	replies.With(map[string]string{"dst": findNode(uint8(body.ID), nodes)}).Inc()
	return body, src, nil
}

func logICMPResponse(echo *icmp.Echo, src net.Addr) {
	log.Debugf("ICMP echo reply from %s id %d", src, echo.ID)
}

func main() {
	flag.Parse()
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	// Load config
	var config Config
	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("unable to read config file: %s", err)
	}
	if err = yaml.Unmarshal(configBytes, &config); err != nil {
		log.Fatalf("unable to parse config file: %s", err)
	}

	// Load targets
	targetsBytes, err := os.ReadFile(*targetsFile)
	if err != nil {
		log.Fatalf("unable to read targets file: %s", err)
	}
	targets := strings.Split(string(targetsBytes), "\n")

	requests = promauto.NewCounter(prometheus.CounterOpts{
		Name:        "verfploeter_requests",
		ConstLabels: map[string]string{"src": findNode(config.ID, config.Nodes)},
	})
	replies = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name:        "verfploeter_replies",
			ConstLabels: map[string]string{"src": findNode(config.ID, config.Nodes)},
		}, []string{"dst"},
	)

	log.Infof("Starting go-verfploeter %s id %d source %s and %s probing %d targets every %s",
		version, config.ID,
		config.Probe.Source4, config.Probe.Source6,
		len(targets), config.Probe.Interval)

	// Open ICMP listeners
	pc4, err = icmp.ListenPacket("ip4:icmp", config.Probe.Source4)
	if err != nil {
		log.Fatalf("unable to listen on IPv4: %s", err)
	}
	defer pc4.Close()

	pc6, err = icmp.ListenPacket("ip6:icmp", config.Probe.Source6)
	if err != nil {
		log.Fatalf("unable to listen on IPv6: %s", err)
	}
	defer pc6.Close()

	// Start IPv4 echo listener
	go func() {
		for {
			reply, src, err := readEchoReply(pc4, config.Nodes)
			if err != nil {
				log.Warn(err)
				continue
			}
			logICMPResponse(reply, src)
		}
	}()

	// Start IPv4 echo listener
	go func() {
		for {
			reply, src, err := readEchoReply(pc6, config.Nodes)
			if err != nil {
				log.Warn(err)
				continue
			}
			logICMPResponse(reply, src)
		}
	}()

	// Start metrics listener
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Fatal(http.ListenAndServe(config.Listen, nil))
	}()

	// Send the probes on a ticker
	probeTicker := time.NewTicker(config.Probe.Interval)
	for ; true; <-probeTicker.C { // Tick once at start
		// Pick random target
		target := targets[rand.Intn(len(targets))]
		log.Debugf("Sending probe to %s", target)
		requests.Inc()
		if err := icmpProbe(target, int(config.ID)); err != nil {
			log.Warn(err)
		}
	}
}
