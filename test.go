package main

import (
    "fmt"
    "time"
    "./src"
)

func StartMonitor(device string) error {
    fmt.Printf("Started %s\n", time.Now())

    mon := PacketSniffer.Start(device)

    for {
	select {
	case p := <-mon.Receive():
            fmt.Printf("TimeStamp: %s, Url: %s\n", p.TimeStamp, p.Url)
	}
    }

    return nil
}

func main() {
    // start ethernet monitor on en0 network device
    StartMonitor("en0")
    
    // block io on main thread
    select {}
}
