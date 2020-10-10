package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/grepplabs/spring-config-decryptor/pkg/decryptor"
)

const (
	defaultEnvEncryptKey = "ENCRYPT_KEY"
)

var (
	inputFile  = flag.String("f", "-", `The file name to decrypt. Use '-' for stdin.`)
	outputFile = flag.String("o", "-", `The file to write the result to. Use '-' for stdout.`)
	keyFile    = flag.String("k", "", fmt.Sprintf("The file with RSA private key. If empty the key is read from environment variable %s ", defaultEnvEncryptKey))
)

func main() {
	flag.Parse()

	var (
		key []byte
		err error
	)

	if len(*keyFile) != 0 {
		key, err = ioutil.ReadFile(*keyFile)
		if err != nil {
			exitOnError("key file reading error: %v", err)
		}
	} else {
		value := os.Getenv(defaultEnvEncryptKey)
		if value == "" {
			exitOnError("missing private key error, provide key in the env variable %s or use -k flag", defaultEnvEncryptKey)
		}
		key = []byte(value)
	}

	var input io.Reader
	if *inputFile == "-" {
		input = os.Stdin
	} else {
		f, err := os.Open(*inputFile)
		if err != nil {
			exitOnError("input open file error: %v", err)
		}
		defer f.Close()
		input = f
	}

	var output io.Writer
	if *outputFile == "-" {
		output = os.Stdout
	} else {
		// do not truncate, append if already exists
		f, err := os.OpenFile(*outputFile, os.O_WRONLY|os.O_CREATE, 0664)
		if err != nil {
			exitOnError("output open file error: %v", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				exitOnError("output close error: %v", err)
			}
		}()
		output = f
	}

	dcr, err := decryptor.NewDecryptor(key)
	if err != nil {
		exitOnError("create decryptor error: %v", err)
		return
	}
	err = dcr.Decrypt(output, input)
	if err != nil {
		exitOnError("decrypt error: %v", err)
	}
}

func exitOnError(format string, a ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format, a...)
	_, _ = fmt.Fprintln(os.Stderr, "")
	os.Exit(1)
}
