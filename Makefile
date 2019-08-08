#LDFLAGS = -s -w

all:
	rm -f restrict
	GOOS=linux GOARCH=amd64 go build -o restrict main.go
	docker build -t restrict .

