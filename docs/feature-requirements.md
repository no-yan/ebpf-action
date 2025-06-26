# Feature Requirements for eBPF-based CI/CD Security Monitoring Tool

## 1. Overview

This document outlines the functional requirements for an eBPF-based security monitoring tool designed to detect and report potential supply chain attacks within the GitHub Actions (GitHub-hosted runner) environment. The tool will leverage eBPF for kernel-level monitoring to identify threats that are difficult to detect with conventional security tools.

## 2. Goal

- To provide visibility into security risks within the GitHub Actions execution environment.
- To detect and prevent information leakage (e.g., secrets, source code) caused by malicious build scripts or dependencies.
- To provide developers with actionable threat intelligence and context to maintain a secure CI/CD pipeline.

## 3. Scope

### 3.1. In-Scope
- **Target Environment:** GitHub Actions (specifically GitHub-hosted runners like Ubuntu).
- **Monitoring Target:** Processes executed within the `run` steps of a workflow.

### 3.2. Out-of-Scope
- Monitoring for vulnerabilities in the GitHub Actions platform itself.
- Monitoring of the host OS for self-hosted runners (though technically extensible).

## 4. Functional Requirements

### FR-1: Network Monitoring and Blocking

#### FR-1.1: Monitor Outbound Network Connections
- **Description:** Monitor all outbound TCP/UDP connections initiated by any process within the workflow.
- **Data to Collect:**
    - Timestamp
    - Process Information (PID, Command Line, Parent Process)
    - Destination IP Address and Port
    - Protocol (TCP/UDP)
    - Associated DNS query (if possible)
- **Implementation Hint:** Attach a kprobe to kernel functions like `tcp_connect` to hook connection attempts.

#### FR-1.2: Block User-Specified IP/Domains
- **Description:** Actively block network connections to a user-defined blocklist of IP addresses or domain names.
- **Configuration:** The blocklist should be configurable via a repository file (e.g., `.github/security.yml`) or environment variables.
- **Action:** If a connection attempt to a blocked destination is detected, the corresponding syscall (e.g., `connect`) should be forced to fail.
- **Reporting:** Log and report any blocked connection attempts, including the source process and the destination.
- **Implementation Hint:** Use LSM (Linux Security Modules) hooks like `socket_connect` or hook the `connect` syscall and return an error.

### FR-2: Secret File Access Monitoring

#### FR-2.1: Monitor Access to Sensitive Files
- **Description:** Monitor read/write access to files matching user-defined patterns (e.g., `*.pem`, `id_rsa`, `credentials.json`).
- **Configuration:** Allow users to specify file patterns (glob or regex) in the configuration file.
- **Data to Collect:**
    - Timestamp
    - Process Information (PID, Command Line)
    - Absolute path of the accessed file
    - Access type (Read, Write)
- **Reporting:** Report which process accessed which sensitive file. **IMPORTANT: The content of the file must not be collected or reported.**
- **Implementation Hint:** Hook the `sys_enter_openat` tracepoint to check the file path and access flags.

### FR-3: Memory-Resident Secret Access Monitoring

#### FR-3.1: Monitor Access to Secrets in Environment Variables
- **Description:** Monitor processes that attempt to read environment variables commonly used for secrets (e.g., those set via GitHub Actions Secrets). This serves as a practical proxy for monitoring memory access to secrets.
- **Configuration:** Monitor variables with a specific prefix (e.g., `SECRET_`) or a user-defined list of variable names.
- **Data to Collect:**
    - Timestamp
    - Process Information (PID, Command Line)
    - Name of the environment variable being accessed.
- **Implementation Hint:** Attach uprobes to libc functions like `getenv`, or monitor access to `/proc/[pid]/environ`.

#### FR-3.2: Monitor Inter-Process Memory Reading
- **Description:** Monitor highly suspicious behavior where one process attempts to read the memory space of another process.
- **Target System Calls:** `ptrace`, `process_vm_readv`.
- **Data to Collect:**
    - Timestamp
    - Source Process Information (PID, Command Line)
    - Target Process Information (PID, Command Line)
- **Reporting:** This behavior should be reported as a high-severity alert, as it is a strong indicator of an attack.

### FR-4: Event Reporting

#### FR-4.1: Event Collection and Aggregation
- **Description:** A user-space agent will collect and store all events detected by the eBPF programs (from FR-1 to FR-3) during the workflow run.
- **Implementation Hint:** The eBPF programs should send events to the user-space agent with low overhead using a ring buffer or perf buffer.

#### FR-4.2: End-of-Job Report Generation
- **Description:** Generate a consolidated report of all collected events when the workflow job completes (on success or failure).
- **Trigger:** The report generation command should be executed in a `post` job step in the GitHub Actions workflow.
- **Report Formats:**
    - **JSON:** A detailed, machine-readable format.
    - **Markdown:** A human-readable summary, suitable for posting in PR comments or GitHub Issues.

#### FR-4.3: Report Submission
- **Description:** Submit the generated report in a way that is accessible to the user.
- **Submission Methods (configurable):**
    - Upload as a GitHub Actions Artifact.
    - [Optional] Post a summary as a comment on the relevant Pull Request.
    - [Optional] Send the JSON report to a specified webhook endpoint.

## 5. Non-Functional Requirements

### NF-1: Performance
- The monitoring overhead should be minimal, with a target of less than 5% increase in build time.

### NF-2: Portability
- The tool must use eBPF CO-RE (Compile Once - Run Everywhere) to run on various kernel versions used by GitHub-hosted runners without requiring recompilation.

### NF-3: Usability
- Installation and setup should be simple, ideally by adding a GitHub Action from the marketplace to a workflow and placing a configuration file in the repository.

### NF-4: Security
- The tool itself must not become a new attack vector. It should run with the minimum required privileges.
- The design must prevent the leakage of sensitive data (e.g., secret contents) from the collected telemetry.

## 6. Example Usage Scenario

### 6.1. Workflow Configuration (`.github/workflows/ci.yml`)

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: eBPF Security Monitor
        uses: your-org/ebpf-security-action@v1
        with:
          config-path: '.github/security.yml'

      - name: Build and Test
        run: |
          # Malicious script could be hidden in a dependency
          npm install
          npm test

      # The eBPF monitor action will automatically generate a report in a post-job step
```

### 6.2. Tool Configuration File (`.github/security.yml`)

```yaml
network:
  block:
    - "1.2.3.4"      # Malicious IP
    - "evil-domain.com" # Malicious Domain

files:
  watch_read:
    - "**/credentials.json"
    - "**/*.pem"
    - "**/id_rsa"
```

### 6.3. Execution Flow

1.  A developer adds the `ebpf-security-action` to their workflow.
2.  The action starts, loads eBPF probes into the kernel, and begins monitoring in the background.
3.  The `Build and Test` step runs. Any suspicious activity (e.g., attempt to connect to `evil-domain.com`, read `credentials.json`) is detected and logged by the eBPF probes.
4.  After the job finishes, the action's `post` step executes, aggregates all events, generates a report, and uploads it as a job artifact.
5.  The developer can review the report from the workflow run's artifacts page to understand what happened.
