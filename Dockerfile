# Build
FROM golang:1.26-alpine AS build

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /bin/your-ip .

# Runtime
FROM scratch

COPY --from=build /bin/your-ip /your-ip

EXPOSE 8080
ENV PORT=8080

ENTRYPOINT ["/your-ip"]
