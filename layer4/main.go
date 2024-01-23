package main

import (
    "log"
    "os"
    "os/signal"
    "time"
	"net"

    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf"
)

func main() {
    // Remove resource limits for kernels <5.11.
    if err := rlimit.RemoveMemlock(); err != nil { 
        log.Fatal("Removing memlock:", err)
    }

    // Load the compiled eBPF ELF and load it into the kernel.
    var objs layer4Objects 
    if err := loadLayer4Objects(&objs, nil); err != nil {
        log.Fatal("Loading eBPF objects:", err)
    }
    defer objs.Close() 

    ifname := "wlp3s0" // Change this to an interface on your machine.
    iface, err := net.InterfaceByName(ifname)
    if err != nil {
        log.Fatalf("Getting interface %s: %s", ifname, err)
    }

    // Attach count_packets to the network interface.
    link, err := link.AttachXDP(link.XDPOptions{ 
        Program:   objs.GetPacketProtocol,
        Interface: iface.Index,
    })
    if err != nil {
        log.Fatal("Attaching XDP:", err)
    }
    defer link.Close() 

    log.Printf("Analysing incoming packets on %s..", ifname)

    tick := time.Tick(time.Second)
    stop := make(chan os.Signal, 5)
    signal.Notify(stop, os.Interrupt)
    for {
        select {
        case <-tick:
        //    log.Print(objs.ProtocolCount)
			printMap(objs.ProtocolCount)
            if err != nil {
                log.Fatal("Map lookup:", err)
            }
        case <-stop:
            log.Print("Received signal, exiting..")
            return
        }
    }
}

func printMap (protocol_map *ebpf.Map) {

	// Iterate through the map
    var key uint32
	var value uint64
    iterator := protocol_map.Iterate()
    for iterator.Next(&key, &value) {
		if value != 0 && key !=0 {
			protocolName := protocolNumberToName(key)
        	log.Printf("Key: %d, Protocol Name: %s Value: %d\n", key, protocolName, value)
		}
    }
    if err := iterator.Err(); err != nil {
        log.Fatalf("Error during map iteration: %v", err)
    }
}

func protocolNumberToName(protocolNumber uint32) string {
	var protocols = map[int]string{
        1:   "ICMP",
        2:   "IGMP",
        3:   "GGP",
        4:   "IP-in-IP",
        5:   "ST",
        6:   "TCP",
        7:   "CBT",
        8:   "EGP",
        9:   "IGP",
        10:  "BBN-RCC-MON",
        11:  "NVP-II",
        12:  "PUP",
        13:  "ARGUS",
        14:  "EMCON",
        15:  "XNET",
        16:  "CHAOS",
        17:  "UDP",
        18:  "MUX",
        19:  "DCN-MEAS",
        20:  "HMP",
        21:  "PRM",
        22:  "XNS-IDP",
        23:  "TRUNK-1",
        255: "Reserved",
    }	

	for k, v := range protocols {
		if k == int(protocolNumber) {
			return v
		}
	}

	return "unknown"
}