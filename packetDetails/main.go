package packetdetails

import (
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/ringbuf"
)

func main() {

	var objs packetDetailsObjects
	if err := loadPacketDetailsObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ring, err := ringbuf.NewReader(objs.Rb)
	if err != nil {
		log.Fatal("Unable to open ring buffer")
	}
	defer ring.Close()

	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	// Read Ring Buffer
	record, err := ring.Read()
	if err != nil{
			log.Print("Unable to retrieve record")
	} else {
		log.Print(record)
	}


	for {
		select{
		case <- stop:
			log.Print("Received signal, exiting..")
		}
	}


}
