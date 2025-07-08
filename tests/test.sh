#!/bin/bash
set -euo pipefail

sudo docker buildx bake --load
trap '$(sudo docker rm -f $(sudo docker ps -aq --filter "name=bee-trace-container-") 2>/dev/null ) 2>/dev/null || true' EXIT

function cleanup () {
	local tmp_dir
	tmp_dir="$1"
	rm -rf "$tmp_dir"
}

function assert_file_monitor () {
	local target="$1"
	local expected="$2"

	local container_name="bee-trace-container-$(date +%s%N)"
	local tmp_dir=$(mktemp -d -t bee-trace-XXXXXXXXXX)

	sudo docker run \
		--name "$container_name" \
		--cap-add=CAP_BPF --cap-add=CAP_PERFMON \
		-d \
		-v /sys/kernel/tracing:/sys/kernel/tracing \
		myapp --probe-type file_monitor \
		>/dev/null

	trap 'cleanup "$tmp_dir"' RETURN

	sleep 1

	echo "read from $target" > "$tmp_dir/$target"
	cat "$tmp_dir/$target"

	result=$(sudo docker logs "${container_name}" 2>&1 | grep -E "(id_rsa|credentials|\.env|\.pem)"  || true) # if not found, grep returns non-zero

	if [[ "$expected" == "true" && -n "$result" ]] ||  [[ "$expected" == "false" && -z "$result" ]]; then 
		return 0
	else
		echo "FAILURE: Test expectation not met."
		echo "  - Expected Match: $expected"
		if [[ -n "$result" ]]; then
			echo "  - Actual: Found a match."
			echo "  - Log Output: $result"
		else
			echo "  - Actual: Did not find a match."
		fi

		return 1
	fi
}

function assert_network_monitor () {
	local test_type="$1"
	local expected="$2"

	local container_name="bee-trace-container-$(date +%s%N)"

	sudo docker run \
		--name "$container_name" \
		--cap-add=CAP_BPF --cap-add=CAP_PERFMON \
		-d \
		-v /sys/kernel/tracing:/sys/kernel/tracing \
		myapp --probe-type network_monitor \
		>/dev/null

	sleep 1

	# Trigger network activity based on test type
	case "$test_type" in
		"http")
			sudo docker exec "$container_name" sh -c "wget -q -O /dev/null http://example.com 2>/dev/null || true"
			;;
		"https")
			sudo docker exec "$container_name" sh -c "wget -q -O /dev/null https://example.com 2>/dev/null || true"
			;;
		"dns")
			sudo docker exec "$container_name" sh -c "nslookup example.com >/dev/null 2>&1 || true"
			;;
	esac

	sleep 1

	result=$(sudo docker logs "${container_name}" 2>&1 | grep -E "(TCP|UDP|Network)" || true)

	if [[ "$expected" == "true" && -n "$result" ]] ||  [[ "$expected" == "false" && -z "$result" ]]; then 
		return 0
	else
		echo "FAILURE: Network monitor test expectation not met."
		echo "  - Test Type: $test_type"
		echo "  - Expected Match: $expected"
		if [[ -n "$result" ]]; then
			echo "  - Actual: Found network events."
			echo "  - Log Output: $result"
		else
			echo "  - Actual: Did not find network events."
		fi

		return 1
	fi
}

function assert_memory_monitor () {
	local test_type="$1"
	local expected="$2"

	local container_name="bee-trace-container-$(date +%s%N)"

	sudo docker run \
		--name "$container_name" \
		--cap-add=CAP_BPF --cap-add=CAP_PERFMON --cap-add=CAP_SYS_PTRACE \
		-d \
		-v /sys/kernel/tracing:/sys/kernel/tracing \
		myapp --probe-type memory_monitor \
		>/dev/null

	sleep 1

	# Create test processes and trigger memory access
	case "$test_type" in
		"ptrace")
			# Create a simple test program and ptrace it
			sudo docker exec "$container_name" sh -c 'echo "int main(){return 0;}" > /tmp/test.c && gcc -o /tmp/test /tmp/test.c 2>/dev/null || true'
			sudo docker exec "$container_name" sh -c 'strace -o /dev/null /tmp/test 2>/dev/null || true'
			;;
		"proc_mem")
			# Try to read /proc/self/mem
			sudo docker exec "$container_name" sh -c 'dd if=/proc/self/mem of=/dev/null bs=1 count=1 2>/dev/null || true'
			;;
	esac

	sleep 1

	result=$(sudo docker logs "${container_name}" 2>&1 | grep -E "(Memory access|ptrace|process_vm)" || true)

	if [[ "$expected" == "true" && -n "$result" ]] ||  [[ "$expected" == "false" && -z "$result" ]]; then 
		return 0
	else
		echo "FAILURE: Memory monitor test expectation not met."
		echo "  - Test Type: $test_type"
		echo "  - Expected Match: $expected"
		if [[ -n "$result" ]]; then
			echo "  - Actual: Found memory access events."
			echo "  - Log Output: $result"
		else
			echo "  - Actual: Did not find memory access events."
		fi

		return 1
	fi
}

# File monitor tests
echo "🔍 Testing file_monitor..."
assert_file_monitor id_rsa true
assert_file_monitor .env true
assert_file_monitor go.mod false

# Network monitor tests
echo "🌐 Testing network_monitor..."
assert_network_monitor http true
assert_network_monitor https true
assert_network_monitor dns true

# Memory monitor tests
echo "🧠 Testing memory_monitor..."
assert_memory_monitor ptrace true
assert_memory_monitor proc_mem true

# All probe types test
echo "🎯 Testing all probe types..."
function assert_all_probes () {
	local container_name="bee-trace-container-$(date +%s%N)"
	local tmp_dir=$(mktemp -d -t bee-trace-XXXXXXXXXX)

	sudo docker run \
		--name "$container_name" \
		--cap-add=CAP_BPF --cap-add=CAP_PERFMON --cap-add=CAP_SYS_PTRACE \
		-d \
		-v /sys/kernel/tracing:/sys/kernel/tracing \
		myapp --probe-type all \
		>/dev/null

	trap 'cleanup "$tmp_dir"' RETURN

	sleep 1

	# Trigger file access
	echo "secret data" > "$tmp_dir/id_rsa"
	cat "$tmp_dir/id_rsa"

	# Trigger network activity
	sudo docker exec "$container_name" sh -c "wget -q -O /dev/null http://example.com 2>/dev/null || true"

	# Trigger memory access
	sudo docker exec "$container_name" sh -c 'strace -o /dev/null ls 2>/dev/null || true'

	sleep 2

	local logs=$(sudo docker logs "${container_name}" 2>&1)
	
	# Check for all types of events
	local file_events=$(echo "$logs" | grep -E "(id_rsa|SENSITIVE)" || true)
	local network_events=$(echo "$logs" | grep -E "(TCP|UDP|Network)" || true)
	local memory_events=$(echo "$logs" | grep -E "(Memory access|ptrace)" || true)

	if [[ -n "$file_events" && -n "$network_events" && -n "$memory_events" ]]; then
		echo "✅ All probe types working correctly"
		return 0
	else
		echo "FAILURE: Not all probe types detected events"
		[[ -z "$file_events" ]] && echo "  - Missing: File access events"
		[[ -z "$network_events" ]] && echo "  - Missing: Network events"
		[[ -z "$memory_events" ]] && echo "  - Missing: Memory access events"
		return 1
	fi
}

assert_all_probes

# Command filtering test
echo "🔎 Testing command filtering..."
function assert_command_filter () {
	local container_name="bee-trace-container-$(date +%s%N)"

	sudo docker run \
		--name "$container_name" \
		--cap-add=CAP_BPF --cap-add=CAP_PERFMON \
		-d \
		-v /sys/kernel/tracing:/sys/kernel/tracing \
		myapp --probe-type network_monitor --command "wget" \
		>/dev/null

	sleep 1

	# Trigger with wget (should be logged)
	sudo docker exec "$container_name" sh -c "wget -q -O /dev/null http://example.com 2>/dev/null || true"
	
	# Trigger with curl (should NOT be logged)
	sudo docker exec "$container_name" sh -c "curl -s http://example.com >/dev/null 2>&1 || true"

	sleep 1

	local logs=$(sudo docker logs "${container_name}" 2>&1)
	local wget_events=$(echo "$logs" | grep -E "wget.*TCP" || true)
	local curl_events=$(echo "$logs" | grep -E "curl.*TCP" || true)

	if [[ -n "$wget_events" && -z "$curl_events" ]]; then
		echo "✅ Command filtering working correctly"
		return 0
	else
		echo "FAILURE: Command filtering not working as expected"
		[[ -z "$wget_events" ]] && echo "  - Missing: wget events"
		[[ -n "$curl_events" ]] && echo "  - Unexpected: curl events found"
		return 1
	fi
}

assert_command_filter

# Duration test
echo "⏱️  Testing duration option..."
function assert_duration () {
	local container_name="bee-trace-container-$(date +%s%N)"
	local start_time=$(date +%s)

	sudo docker run \
		--name "$container_name" \
		--cap-add=CAP_BPF --cap-add=CAP_PERFMON \
		-v /sys/kernel/tracing:/sys/kernel/tracing \
		myapp --probe-type file_monitor --duration 3 \
		>/dev/null

	local end_time=$(date +%s)
	local duration=$((end_time - start_time))

	# Check container stopped
	local status=$(sudo docker ps -a --filter "name=$container_name" --format "{{.Status}}")

	if [[ "$status" == *"Exited"* ]] && [[ $duration -ge 3 ]] && [[ $duration -le 5 ]]; then
		echo "✅ Duration option working correctly (ran for ${duration}s)"
		return 0
	else
		echo "FAILURE: Duration option not working"
		echo "  - Expected: Container to exit after ~3 seconds"
		echo "  - Actual: Duration was ${duration}s, status: $status"
		return 1
	fi
}

assert_duration

echo "✅ All tests passed!"

