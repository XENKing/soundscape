FROM golang:alpine as build
RUN apk add --no-cache git gcc musl-dev
WORKDIR /go/src/github.com/xenking/soundscape
ARG BUILD_VERSION=2.6
ENV GODEBUG="netdns=go http2server=0"
ENV GOPATH="/go"
RUN go get \
    github.com/go-bindata/go-bindata/... \
    github.com/PuerkitoBio/goquery \
    github.com/armon/circbuf \
    github.com/disintegration/imaging \
    github.com/dustin/go-humanize \
    github.com/julienschmidt/httprouter \
    github.com/eduncan911/podcast \
    github.com/xenking/ytdl \
    go.uber.org/zap \
    golang.org/x/crypto/acme/autocert \
    github.com/jinzhu/gorm \
    github.com/jinzhu/gorm/dialects/mysql \
    github.com/jinzhu/gorm/dialects/sqlite \
    github.com/go-sql-driver/mysql \
    github.com/gorilla/securecookie \
    github.com/dgrijalva/jwt-go \
    golang.org/x/crypto/bcrypt
COPY *.go ./
COPY internal ./internal
COPY static ./static
COPY templates ./templates
RUN go-bindata --pkg main static/... templates/... && \
    go fmt && \
    go vet --all

RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
    go build -v --compiler gc --ldflags "-extldflags -static -s -w -X main.version=${BUILD_VERSION}" -o /usr/bin/soundscape

FROM alpine:latest
RUN apk --no-cache add \
    curl \
    ffmpeg \
    wget
WORKDIR /data
COPY --from=build /usr/bin/soundscape /usr/local/bin/soundscape
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/soundscape /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "/usr/local/bin/entrypoint.sh" ]
