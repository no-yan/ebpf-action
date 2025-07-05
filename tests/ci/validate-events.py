#!/usr/bin/env python3
"""
Event validator for eBPF CI tests
Parses bee-trace logs and validates that expected events were detected
"""

import argparse
import json
import re
import sys
from datetime import datetime
from typing import Dict, List, Optional, Set


class EventValidator:
    """Validates eBPF events from bee-trace logs"""
    
    def __init__(self, log_file: str, test_results: str, event_type: str):
        self.log_file = log_file
        self.test_results = test_results
        self.event_type = event_type
        self.events: List[Dict] = []
        
    def parse_events(self) -> None:
        """Parse events from bee-trace log file"""
        
        # Patterns for different event types
        patterns = {
            'file': re.compile(r'Event sent successfully.*FILE.*path=([^\s,]+).*severity=(\w+)'),
            'network': re.compile(r'Event sent successfully.*(?:TCP_CONNECT|UDP_SEND).*addr=([^\s,]+).*port=(\d+)'),
            'memory': re.compile(r'Event sent successfully.*(?:PTRACE|PROCESS_VM_READV).*target_pid=(\d+)')
        }
        
        pattern = patterns.get(self.event_type)
        if not pattern:
            print(f"Unknown event type: {self.event_type}")
            return
        
        with open(self.log_file, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    event = self._parse_event_from_match(match, line)
                    if event:
                        self.events.append(event)
    
    def _parse_event_from_match(self, match, line: str) -> Optional[Dict]:
        """Extract event details from regex match"""
        
        event = {
            'timestamp': self._extract_timestamp(line),
            'raw_line': line.strip()
        }
        
        if self.event_type == 'file':
            event['path'] = match.group(1)
            event['severity'] = match.group(2)
            event['type'] = 'file_access'
            
        elif self.event_type == 'network':
            event['address'] = match.group(1)
            event['port'] = int(match.group(2))
            event['type'] = 'network_connection'
            
        elif self.event_type == 'memory':
            event['target_pid'] = int(match.group(1))
            event['type'] = 'memory_access'
            
        return event
    
    def _extract_timestamp(self, line: str) -> str:
        """Extract timestamp from log line"""
        # Try to find ISO timestamp
        iso_pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
        match = re.search(iso_pattern, line)
        if match:
            return match.group(1)
        return datetime.now().isoformat()
    
    def validate_test_results(self) -> bool:
        """Validate that expected events were detected"""
        
        with open(self.test_results, 'r') as f:
            results = json.load(f)
        
        all_passed = True
        
        for test in results.get('tests', []):
            if test['status'] != 'passed':
                continue
                
            # Check if we have corresponding events
            test_name = test['name']
            expected_events = self._get_expected_events(test_name)
            
            found_events = self._find_matching_events(expected_events)
            
            if not found_events:
                print(f"WARNING: Test '{test_name}' passed but no events found in logs")
                test['warning'] = 'No events found in logs'
                all_passed = False
        
        # Update results file with warnings
        with open(self.test_results, 'w') as f:
            json.dump(results, f, indent=2)
        
        return all_passed
    
    def _get_expected_events(self, test_name: str) -> Set[str]:
        """Get expected event patterns for a test"""
        
        # Map test names to expected patterns
        expectations = {
            # File tests
            'SSH Key Access': {'id_rsa', '.ssh/test_key'},
            'Environment File Access': {'.env'},
            'Certificate Access': {'.pem', '.key', '.crt'},
            'Credential File Access': {'credentials'},
            'Git Config Access': {'.git/config', '.gitconfig'},
            'Hidden File Access': {'.hidden', '.docker', '.kube'},
            'Database Config Access': {'database.yml', 'mongod.conf', '.pgpass'},
            'Container Secrets Access': {'dockercfg', 'secrets/'},
            
            # Network tests (if implemented)
            'Suspicious Port Access': {'4444', '6667', '31337'},
            'Rapid Connections': {'connect_burst'},
            
            # Memory tests (if implemented)
            'Process Memory Read': {'ptrace', 'process_vm_readv'},
        }
        
        return expectations.get(test_name, set())
    
    def _find_matching_events(self, patterns: Set[str]) -> List[Dict]:
        """Find events matching the given patterns"""
        
        matching = []
        
        for event in self.events:
            for pattern in patterns:
                if self._event_matches_pattern(event, pattern):
                    matching.append(event)
                    break
        
        return matching
    
    def _event_matches_pattern(self, event: Dict, pattern: str) -> bool:
        """Check if an event matches a pattern"""
        
        if self.event_type == 'file':
            return pattern.lower() in event.get('path', '').lower()
        elif self.event_type == 'network':
            return str(pattern) == str(event.get('port', ''))
        elif self.event_type == 'memory':
            return pattern in event.get('raw_line', '').lower()
        
        return False
    
    def generate_report(self) -> None:
        """Generate a summary report of detected events"""
        
        print(f"\n=== Event Validation Report ===")
        print(f"Log file: {self.log_file}")
        print(f"Event type: {self.event_type}")
        print(f"Total events parsed: {len(self.events)}")
        
        if self.event_type == 'file':
            # Group by severity
            by_severity = {}
            for event in self.events:
                severity = event.get('severity', 'UNKNOWN')
                by_severity.setdefault(severity, []).append(event)
            
            print("\nEvents by severity:")
            for severity, events in sorted(by_severity.items()):
                print(f"  {severity}: {len(events)} events")
                
                # Show sample paths
                sample_paths = [e.get('path', 'N/A') for e in events[:3]]
                for path in sample_paths:
                    print(f"    - {path}")
                if len(events) > 3:
                    print(f"    ... and {len(events) - 3} more")
        
        elif self.event_type == 'network':
            # Group by port
            by_port = {}
            for event in self.events:
                port = event.get('port', 0)
                by_port.setdefault(port, []).append(event)
            
            print("\nConnections by port:")
            for port, events in sorted(by_port.items()):
                print(f"  Port {port}: {len(events)} connections")
        
        elif self.event_type == 'memory':
            # Group by access type
            ptrace_count = sum(1 for e in self.events if 'ptrace' in e.get('raw_line', '').lower())
            vm_read_count = sum(1 for e in self.events if 'process_vm_readv' in e.get('raw_line', '').lower())
            
            print("\nMemory access events:")
            print(f"  ptrace: {ptrace_count}")
            print(f"  process_vm_readv: {vm_read_count}")


def main():
    parser = argparse.ArgumentParser(description='Validate eBPF events from bee-trace logs')
    parser.add_argument('--log-file', required=True, help='Path to bee-trace log file')
    parser.add_argument('--test-results', required=True, help='Path to test results JSON file')
    parser.add_argument('--event-type', required=True, choices=['file', 'network', 'memory'],
                        help='Type of events to validate')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    
    args = parser.parse_args()
    
    validator = EventValidator(args.log_file, args.test_results, args.event_type)
    
    # Parse events from log
    validator.parse_events()
    
    # Validate against test results
    success = validator.validate_test_results()
    
    # Generate report
    if args.verbose:
        validator.generate_report()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()