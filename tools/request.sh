set -x
curl -I -s -H "$1" http://localhost:8000/?times=[1-100] > /dev/null &
curl_pid=$!
echo "curl pid: $curl_pid"
wait $curl_pid

