FROM golang:1.20-bullseye

ARG commit=main
ARG network=mainnet

WORKDIR /workspace

COPY go.mod go.sum ./
COPY . ./

RUN go mod download
RUN go build -tags ${network}} -o server .