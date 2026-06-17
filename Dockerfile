FROM golang:1.26.3 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG KMS_ENABLED=false
RUN if [ "$KMS_ENABLED" = "true" ]; then \
    (cd kms && go mod download) && go work init && go work use . ./kms && \
    CGO_ENABLED=0 GOEXPERIMENT=runtimesecret go build -tags kms -o csi-secret-age . ; \
    else \
    CGO_ENABLED=0 GOEXPERIMENT=runtimesecret go build -o csi-secret-age . ; \
    fi

FROM gcr.io/distroless/static-debian12
WORKDIR /
COPY --from=builder /app/csi-secret-age /csi-secret-age
ENTRYPOINT ["/csi-secret-age"]
