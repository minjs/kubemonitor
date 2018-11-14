go build -ldflags "-X github.com/Zero-Systems/agent/main.Build=`git rev-parse HEAD`" -o agent agent.go
