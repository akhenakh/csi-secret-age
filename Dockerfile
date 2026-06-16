FROM golang:1.26.3 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOEXPERIMENT=runtimesecret go build -o csi-secret-age .

FROM gcr.io/distroless/static-debian12
WORKDIR /
COPY --from=builder /app/csi-secret-age /csi-secret-age
ENTRYPOINT ["/csi-secret-age"]
