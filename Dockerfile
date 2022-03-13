ARG GOLANG_VERSION=1.17

# Building bouncer
FROM golang:$GOLANG_VERSION as build-env

# Copying source
WORKDIR /go/src/app
COPY . /go/src/app

# Installing dependencies
RUN go get -d -v ./...

# Compiling
RUN go build -o /go/bin/cs-mikrotik-bouncer

FROM gcr.io/distroless/base:nonroot
COPY --from=build-env --chown=nonroot:nonroot /go/bin/cs-mikrotik-bouncer /

# Run as a non root user.
USER nonroot


# Run app
CMD ["/cs-mikrotik-bouncer"]