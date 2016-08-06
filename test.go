package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
	"./src"
)

// Start our monitor
func StartMonitor(device string) error {
	fmt.Printf("Started %s\n", time.Now())

	mon := PacketSniffer.Start(device)

	for {

		select {

		case httpRequest := <-mon.Receive():
			fmt.Printf("%s\n", httpRequest.Host)
		}

		return nil
	}
}
func clear() {
	c := exec.Command("clear")
	c.Stdout = os.Stdout
	err := c.Run()
	if err != nil {
		fmt.Printf("clear err: %s\n", err.Error())
	}
}

/*
c := exec.Command("clear")
c.Stdout = os.Stdout
c.Run()
Don't forget to import "os" and "os/exec".*/
func main() {
	// start ethernet monitor on en0 network device
	go StartMonitor("en0")

	// block io on main thread
	select {}
}
