package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Enter the network interface (e.g., 'eth0'):")
	iface, _ := reader.ReadString('\n')
	iface = strings.TrimSpace(iface)

	fmt.Println("Enter a BPF filter string (e.g., 'tcp and port 80'):")
	filter, _ := reader.ReadString('\n')
	filter = strings.TrimSpace(filter)

	// Open the device for capturing
	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	fmt.Println("Filter set:", filter)
	fmt.Println("Starting packet capture... Press Ctrl+C to exit.")

	// Set up a packet source to process captured packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Read packets in a loop
	for packet := range packetSource.Packets() {
		// Get the TCP layer from the packet
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			// Extract source and destination IP addresses
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				fmt.Printf("SrcIP: %s, DstIP: %s, ", ip.SrcIP, ip.DstIP)
			}

			// Print TCP flags
			fmt.Printf("SYN: %t, ACK: %t, FIN: %t, PSH: %t, URG: %t, RST: %t\n",
				tcp.SYN, tcp.ACK, tcp.FIN, tcp.PSH, tcp.URG, tcp.RST)
		}
	}
}
