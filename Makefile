help:
	echo "help"
server:
	python3 tools/server.py

keepalive:
	./tools/request.sh "Connection: keep-alive" 

nokeepalive:
	./tools/request.sh "Connection: close"

