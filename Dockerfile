FROM golang:1.26.3 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG KMS_ENABLED=false
ARG GCPKMS_ENABLED=false
RUN BUILD_TAGS="" && \
    if [ "$KMS_ENABLED" = "true" ]; then \
        (cd kms && go mod download); \
        BUILD_TAGS="$BUILD_TAGS,kms"; \
    fi && \
    if [ "$GCPKMS_ENABLED" = "true" ]; then \
        (cd gcpkms && go mod download); \
        BUILD_TAGS="$BUILD_TAGS,gcpkms"; \
    fi && \
    if [ -n "$BUILD_TAGS" ]; then \
        go work init && go work use . ./kms 2>/dev/null || true && \
        go work use . ./gcpkms 2>/dev/null || true; \
        CGO_ENABLED=0 GOEXPERIMENT=runtimesecret go build -tags "${BUILD_TAGS#,}" -o csi-secret-age . ; \
    else \
        CGO_ENABLED=0 GOEXPERIMENT=runtimesecret go build -o csi-secret-age . ; \
    fi

FROM gcr.io/distroless/static-debian12
WORKDIR /
COPY --from=builder /app/csi-secret-age /csi-secret-age
ENTRYPOINT ["/csi-secret-age"]
