# Start with the official Go image to build the binary
FROM golang:latest AS builder

# Set the working directory inside the container
WORKDIR /app

# Target linux
ENV GOARCH=arm64
ENV GOOS=linux

# Copy the Go module files
COPY go.mod go.sum main.go ./

# Download the Go module dependencies
RUN go mod download

# Build the Go app (this will create the binary file)
RUN go build -buildmode=pie -o server main.go

# Use a minimal base image (Alpine) to run the binary in a small image
FROM alpine:latest

# Install necessary certificates for TLS
RUN apk --no-cache add ca-certificates

# Set the working directory inside the minimal image
WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/server .

# Expose the port your application is running on (change if necessary)
EXPOSE 4242

# Run the binary
CMD ["./server"]
