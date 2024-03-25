# Start from the official Golang image based on Alpine Linux
FROM golang:alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the source code
COPY . . 

# Download and install the dependencies
RUN go get -d -v ./...

# Build the Go application
RUN go build -o main .

# Expose port 8000 to the outside world
EXPOSE 8000

# Command to run the executable
CMD ["./main"]
