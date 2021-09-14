#!/bin/bash
CGO_ENABLED=0 go build -tags $1 -o server .
