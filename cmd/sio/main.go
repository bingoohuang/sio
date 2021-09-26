// Copyright (C) 2017 Minio Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Ncrypt en/decrypts arbitrary data streams securely.
//
// Without an input file it reads from STDIN and writes to
// STDOUT if no output file is specified.
//
// Usage: sio [FLAGS] [ARGUMENTS...]
//
//    -cipher string   Specify cipher - default: platform depended
//    -d               Decrypt
//    -list            List supported algorithms
//    -p      string   Specify the password - default: prompt for password
//
// Examples:
//
// Encrypt file 'myfile.txt':                  sio ~/myfile.txt ~/myfile.txt.enc
// Decrypt 'myfile.txt.enc' and print content: sio -d ~/myfile.txt
// Encrypt file 'myfile.txt' using unix pipes: cat ~/myfile.txt | sio > ~/myfile.txt.enc
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/bingoohuang/sio"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	codeOK     int = iota // exit successfully
	codeError             // exit because of error
	codeCancel            // exit because of interrupt
)

var (
	cleanChan chan<- int // initialized in init
	cleanFn   = make([]func(int), 0, 3)
)

var (
	listFlag     bool
	decryptFlag  bool
	cipherFlag   string
	passwordFlag string
	kdf          string
)

func boolVar(p *bool, name string, value bool, usage string) {
	flag.BoolVar(p, name, value, fmt.Sprintf("%-8s %s", "", usage))
}

func stringVar(p *string, name string, value string, usage string) {
	flag.StringVar(p, name, value, fmt.Sprintf("%-8s %s", "string", usage))
}

func printFlag(f *flag.Flag) {
	fmt.Fprintf(os.Stderr, "  -%-6s %s\n", f.Name, f.Usage)
}

func init() {
	boolVar(&listFlag, "list", false, "List supported algorithms")
	boolVar(&decryptFlag, "d", false, "Decrypt")
	stringVar(&kdf, "kdf", "hkdf", "KDF scrypt/hkdf")
	stringVar(&cipherFlag, "cipher", "", "Specify cipher - default: platform depended")
	stringVar(&passwordFlag, "p", "", "Specify the password - default: prompt for password")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [FLAGS] [ARGUMENTS...]\n\n", os.Args[0])
		flag.VisitAll(printFlag)

		if sio.SupportsAES {
			fmt.Fprintf(os.Stderr, "\n\nDetected: CPU provides hardware support for AES-GCM.\n")
		}

		os.Exit(codeOK)
	}

	cleanCh := make(chan int, 1)
	cleanChan = cleanCh
	go func() {
		code := <-cleanCh
		for _, f := range cleanFn {
			f(code)
		}
		os.Exit(code)
	}()

	// handle user termination
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cleanCh <- codeCancel // try to exit gracefully
		runtime.Goexit()
	}()
}

var supportedCiphers = [][]string{
	{"AES256", "AES-256 GCM"},
	{"C20P1305", "ChaCha20 Poly1305"},
}

func main() {
	flag.Parse()
	if listFlag {
		printCiphers()
	}

	ciphersuite := cipherSuites()
	in, out := parseIOArgs()
	key := deriveKey(out, in)

	cfg := sio.Config{Key: key, CipherSuites: ciphersuite}
	if decryptFlag {
		decrypt(out, in, cfg)
	} else {
		encrypt(out, in, cfg)
	}
}

func exit(code int) {
	cleanChan <- code
	runtime.Goexit()
}

func printCiphers() {
	fmt.Fprintln(os.Stdout, "Supported ciphers:")
	for _, c := range supportedCiphers {
		fmt.Fprintf(os.Stdout, "\t%-8s : %s\n", c[0], c[1])
	}
	exit(codeOK)
}

var NoopErr = errors.New("default error")

func cipherSuites() []byte {
	switch cipherFlag {
	default:
		checkErr(NoopErr, "Unknown cipher: %s\n", cipherFlag)
		return nil // make compiler happy
	case "":
		return []byte{} // use platform specific cipher
	case "AES256":
		return []byte{sio.AES_256_GCM}
	case "C20P1305":
		return []byte{sio.CHACHA20_POLY1305}
	}
}

func parseIOArgs() (*os.File, *os.File) {
	switch args := flag.Args(); len(args) {
	default:
		checkErr(NoopErr, "Unknown arguments: %s\n", args[2:])
		return nil, nil // make compiler happy
	case 0:
		return os.Stdin, os.Stdout
	case 1:
		in, err := os.Open(args[0])
		if err != nil {
			checkErr(err, "Failed to open '%s': %v\n", args[0], err)
		}
		cleanFn = append(cleanFn, func(code int) { in.Close() })
		return in, os.Stdout
	case 2:
		in, err := os.Open(args[0])
		if err != nil {
			checkErr(err, "Failed to open '%s': %v\n", args[0], err)
		}
		out, err := os.Create(args[1])
		if err != nil {
			checkErr(err, "Failed to create '%s': %v\n", args[1], err)
		}
		cleanFn = append(cleanFn, func(code int) {
			out.Close()
			if code != codeOK { // remove file on error
				os.Remove(out.Name())
			}
		})
		return in, out
	}
}

func readPassword(src *os.File) []byte {
	state, err := terminal.GetState(int(src.Fd()))
	if err != nil {
		checkErr(err, "Failed to read password:", err)
	}
	cleanFn = append(cleanFn, func(code int) {
		stat, _ := terminal.GetState(int(src.Fd()))
		if code == codeCancel && stat != nil && *stat != *state {
			fmt.Fprintln(src, "\nFailed to read password: Interrupted")
		}
		terminal.Restore(int(src.Fd()), state)
	})

	fmt.Fprint(src, "Enter password:")
	password, err := terminal.ReadPassword(int(src.Fd()))
	if err != nil {
		checkErr(err, "Failed to read password:", err)
	}
	fmt.Fprintln(src, "")
	if len(password) == 0 {
		checkErr(err, "Failed to read password: No password")
	}
	return password
}

func deriveKey(dst, src *os.File) []byte {
	password := getPassword(passwordFlag, src)
	salt := getSalt(decryptFlag, dst, src)

	switch kdf {
	case "scrypt":
		key, err := scrypt.Key(password, salt, 32768, 16, 1, 32)
		checkErr(err, "Failed to derive key from password and salt")
		return key
	case "hkdf":
		key := make([]byte, 32)
		r := hkdf.New(sha256.New, password, salt, nil)
		_, err := io.ReadFull(r, key)
		checkErr(err, "Failed to read kdf")

		return key
	default:
		checkErr(NoopErr, "unknown kdf %q", kdf)
		return nil
	}
}

func getSalt(decryptFlag bool, dst *os.File, src *os.File) []byte {
	salt := make([]byte, 32)
	if decryptFlag {
		if _, err := io.ReadFull(src, salt); err != nil {
			checkErr(err, "Failed to read salt from %q", src.Name())
		}
		return salt
	}

	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		checkErr(err, "Failed to generate random salt %q", src.Name())
	}
	if _, err := dst.Write(salt); err != nil {
		checkErr(err, "Failed to write salt to %q", dst.Name())
	}

	return salt
}

func getPassword(pwdFlag string, src *os.File) []byte {
	if pwdFlag != "" {
		return []byte(pwdFlag)
	} else if src == os.Stdin {
		return readPassword(os.Stderr)
	} else {
		return readPassword(os.Stdin)
	}
}

func checkErr(err error, format string, args ...interface{}) {
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, format+"\n", args...)
		if err != NoopErr {
			_, _ = fmt.Fprintf(os.Stderr, "error %s\n", err.Error())
		}
		exit(codeError)
	}
}

func encrypt(dst, src *os.File, cfg sio.Config) {
	if _, err := sio.Encrypt(dst, src, cfg); err != nil {
		checkErr(err, "Failed to encrypt: %q", src.Name())
	}
}

func decrypt(dst, src *os.File, cfg sio.Config) {
	if _, err := sio.Decrypt(dst, src, cfg); err != nil {
		checkErr(err, "Failed to decrypt:  %q", src.Name())
	}
}
