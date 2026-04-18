// Package main implements a fake tor binary used by torpool tests.
//
// It reads its torrc from -f <path>, extracts SocksPort if asked to bind,
// and emits bootstrap-like lines to stderr (to match real tor's
// "Log notice stderr"). Controlled via envvars:
//
//	FAKE_TOR_MODE=bootstrap|silent|slow   (default: bootstrap)
//	FAKE_TOR_STREAM=stderr|stdout         (default: stderr — real tor writes to stderr)
//	FAKE_TOR_BIND=1                       hold the SocksPort like real tor
//	FAKE_TOR_IGNORE_SIGTERM=1             drop SIGTERM to exercise kill-and-wait
package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	mode := getenv("FAKE_TOR_MODE", "bootstrap")
	stream := getenv("FAKE_TOR_STREAM", "stderr")
	doBind := os.Getenv("FAKE_TOR_BIND") == "1"

	// Discover SocksPort from torrc (-f <path>).
	var socksPort int
	for i := 0; i < len(os.Args)-1; i++ {
		if os.Args[i] == "-f" {
			data, err := os.ReadFile(os.Args[i+1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "fake-tor: read torrc:", err)
				os.Exit(2)
			}
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "SocksPort 127.0.0.1:") {
					p, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "SocksPort 127.0.0.1:")))
					if err == nil {
						socksPort = p
					}
				}
			}
		}
	}

	if doBind && socksPort > 0 {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort))
		if err != nil {
			fmt.Fprintln(os.Stderr, "fake-tor: bind:", err)
			os.Exit(3)
		}
		defer ln.Close()
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}

	emit := func(line string) {
		if stream == "stdout" {
			fmt.Fprintln(os.Stdout, line)
		} else {
			fmt.Fprintln(os.Stderr, line)
		}
	}

	switch mode {
	case "bootstrap":
		emit("Apr 18 12:00:00.000 [notice] Bootstrapped 5% (conn)")
		emit("Apr 18 12:00:01.000 [notice] Bootstrapped 100% (done)")
	case "silent":
		emit("Apr 18 12:00:00.000 [notice] Bootstrapped 5% (conn)")
	case "slow":
		time.Sleep(200 * time.Millisecond)
		emit("Apr 18 12:00:00.000 [notice] Bootstrapped 100% (done)")
	default:
		emit("Apr 18 12:00:00.000 [notice] Bootstrapped 100% (done)")
	}

	// Keep running until stdin closes or parent kills us.
	r := bufio.NewReader(os.Stdin)
	for {
		if _, err := r.ReadByte(); err != nil {
			return
		}
	}
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
