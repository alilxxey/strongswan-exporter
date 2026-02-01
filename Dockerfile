FROM golang:1.25 AS build

WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . ./

RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/strongswan-exporter ./cmd/strongswan-exporter

FROM scratch
COPY --from=build /out/strongswan-exporter /strongswan-exporter
EXPOSE 9814
ENTRYPOINT ["/strongswan-exporter"]
