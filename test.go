package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
	"sort"

	"./src"
)

// Start our monitor
func StartMonitor(device string) error {
	fmt.Printf("Started %s\n", time.Now())

	mon := PacketSniffer.Start(device)

	websites := make(map[string]time.Time)

	go func() {
		
		for {
			clear()
			
			for key := range websites {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for key := range keys {
				fmt.Printf("%s: %d\n", key, websites[key])
			}
			
			time.Sleep(time.Second)
		}
	}()

	for {

		select {

		case httpRequest := <-mon.Receive():
			//fmt.Printf("TimeStamp: %s, Url: %s\n", httpRequest.TimeStamp, httpRequest.Url)
			website := websites[httpRequest.Url]

			if website == 0 {
				websites[httpRequest.Url] = 1
			} else {
				websites[httpRequest.Url] += 1
			}
		}
	}

	return nil
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

	StartMonitor("en0")

	select {}
}
