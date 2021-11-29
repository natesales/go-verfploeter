package main

import (
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (
	source4 = "0.0.0.0"
	source6 = "::"

	pc4 *icmp.PacketConn
	pc6 *icmp.PacketConn
)

// icmpProbe sends an ICMP probe to a given target with an ID
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
func readEchoReply(pc *icmp.PacketConn) (*icmp.Echo, net.Addr, error) {
	reply := make([]byte, 1500)
	n, src, err := pc.ReadFrom(reply)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read from icmp.PacketConn: %s", err)
	}

	var proto int
	if ip := net.ParseIP(pc.LocalAddr().String()); ip.To4() != nil {
		proto = 1
	} else {
		proto = 58
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
	return body, src, nil
}

func main() {
	var err error
	pc4, err = icmp.ListenPacket("ip4:icmp", source4)
	if err != nil {
		log.Fatalf("unable to listen on IPv4: %s", err)
	}
	defer pc4.Close()

	pc6, err = icmp.ListenPacket("ip6:icmp", source6)
	if err != nil {
		log.Fatalf("unable to listen on IPv6: %s", err)
	}
	defer pc6.Close()

	// Start IPv4 echo listener
	go func() {
		for {
			reply, src, err := readEchoReply(pc4)
			if err != nil {
				log.Warn(err)
				continue
			}
			log.Infof("IPv4 echo reply from %s id %d", src, reply.ID)
		}
	}()

	// Start IPv4 echo listener
	go func() {
		for {
			reply, src, err := readEchoReply(pc6)
			if err != nil {
				log.Warn(err)
				continue
			}
			log.Infof("IPv6 echo reply from %s id %d", src, reply.ID)
		}
	}()

	// Send the probes on a ticker
	probeTicker := time.NewTicker(2 * time.Second)
	for range probeTicker.C {
		if err := icmpProbe("1.1.1.1", 2021); err != nil {
			log.Warn(err)
		}
	}
}
