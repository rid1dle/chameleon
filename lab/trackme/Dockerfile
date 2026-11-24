# Build TrackMe from vendor/pagpeter_TrackMe (pinned 9d2e865). Certs and config are mounted at run time.
FROM golang:1.24-alpine
RUN apk add --no-cache build-base libpcap-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd/
COPY pkg ./pkg/
COPY static ./static/
RUN go build -o ./out/app ./cmd/main.go
CMD [ "./out/app" ]
