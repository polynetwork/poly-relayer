#!/bin/bash
go build -tags $1 -ldflags "-X google.golang.org/protobuf/reflect/protoregistry.conflictPolicy=warn" -o server .