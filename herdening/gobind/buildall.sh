#!/bin/bash

archs=(
    "linux/amd64"
    "linux/arm64"
    "windows/amd64"
    "windows/arm64"
    "freebsd/amd64"
    "freebsd/arm64"
)


for arch in "${archs[@]}"; do
    os=$(echo $arch | cut -d '/' -f 1)
    goarch=$(echo $arch | cut -d '/' -f 2)
    
    if [ "$os" = "windows" ]; then
        env GOOS=$os GOARCH=$goarch go build -o bin/bind-$arch.exe bind.go
    else
        env GOOS=$os GOARCH=$goarch go build -o bin/bind-$arch bind.go
    fi
done

