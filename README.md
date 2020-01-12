# spring-config-decryptor
Decrypt Spring Cloud Config with values encrypted with asymmetric key


## Overview

spring-config-decryptor is a tool to decrypt Spring Boot configuration with values encrypted with RSA public key using
`spring encrypt` from [Spring Cloud CLI](https://cloud.spring.io/spring-cloud-cli/1.0.x/) toolkit.

The secret values are base64 encoded and start with `{cipher}` prefix.

## Install binary release

1. Download the latest release

   Linux

        curl -Ls https://github.com/grepplabs/spring-config-decryptor/releases/download/v0.0.1/spring-config-decryptor-v0.0.1-linux-amd64.tar.gz | tar xz

   macOS

        curl -Ls https://github.com/grepplabs/spring-config-decryptor/releases/download/v0.0.1/spring-config-decryptor-v0.0.1-darwin-amd64.tar.gz | tar xz

   windows

        curl -Ls https://github.com/grepplabs/spring-config-decryptor/releases/download/v0.0.1/spring-config-decryptor-v0.0.1-windows-amd64.tar.gz | tar xz


2. Move the binary in to your PATH.

    ```
    sudo mv ./spring-config-decryptor /usr/local/bin/spring-config-decryptor
    ```
   
## Building

    make clean build
    
## Usage

    export ENCRYPT_KEY=$(cat private.pem)
    cat configmap.yaml | spring-config-decryptor
    
## Help output

    Usage of spring-config-decryptor:
      -f string
            The file name to decrypt. Use '-' for stdin. (default "-")
      -k string
            The file with RSA private key. If empty the key is read from environment variable ENCRYPT_KEY 
      -o string
            The file to write the result to. Use '-' for stdout. (default "-")
    


