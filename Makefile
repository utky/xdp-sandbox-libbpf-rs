help:
	echo "help"

trace:
	sudo tail -f /sys/kernel/debug/tracing/trace_pipe
server:
	python3 tools/server.py

keepalive:
	./tools/request.sh "Connection: keep-alive" 

nokeepalive:
	./tools/request.sh "Connection: close"

