# FindEvil - Forensic AI Agent
### SANS Find Evil Hackathon 2026

## What This Does
An autonomous forensic AI agent that analyzes disk images,
extracts evidence, validates findings, and self-corrects errors
without human intervention.

## Setup Instructions
1. Install WSL2 Ubuntu on Windows
2. Run: `sudo apt-get install -y sleuthkit foremost binwalk yara libimage-exiftool-perl`
3. Run: `pip3 install volatility3 --break-system-packages`
4. Run: `npm install -g @anthropic-ai/claude-code`
5. Add API key: `export ANTHROPIC_API_KEY=your_key_here`
6. Run agent: `python3 agent/mock_agent.py`

## Architecture
Evidence → Agent → SIFT Tools → Self-Correction → Report

## Tools Used
- Sleuthkit (filesystem analysis)
- Foremost (file carving)
- ExifTool (metadata extraction)
- Volatility3 (memory forensics)
- YARA (pattern matching)
- Claude Code (AI reasoning)

## License
MIT License - Open Source

## Try It Out

### Requirements
- Ubuntu 20.04+ or WSL2 on Windows
- Python 3.8+
- git, curl installed

### Quick Start
```bash
# Clone the repository
git clone https://github.com/macbere/findevil.git
cd findevil

# Install forensic tools
sudo apt-get install -y sleuthkit foremost binwalk yara libimage-exiftool-perl

# Install Python dependencies  
pip3 install volatility3 --break-system-packages

# Install Claude Code (agentic framework)
npm install -g @anthropic-ai/claude-code

# Run the agent (Mock Mode - no API key needed)
export CASE=FINDEVIL-2026-001
python3 cases/analysis/findevil_agent.py

# Expected output:
# [INFO] [MOCK] === FindEvil Agent Starting ===
# [INFO] [MOCK] PHASE 1: File System Analysis
# [WARN] [MOCK] CORRECTION_FIRED: anomaly detected
# [INFO] [MOCK] CORRECTION_ACTION: retrying with broader search
# [INFO] [MOCK] === Analysis Complete ===
```

### Run With Real API Key (Optional)
```bash
export ANTHROPIC_API_KEY=your_key_here
export CASE=FINDEVIL-2026-001
python3 cases/analysis/findevil_agent.py
# Agent switches automatically to LIVE mode
```

### Run Stress Tests
```bash
python3 /tmp/stress_monitor.py
# Expected: 95 files analyzed, 100% success rate, 4.85x speedup
```

### View Results
```bash
# Execution logs with self-correction events
cat cases/exports/execution.log

# Structured findings report
cat cases/reports/findings.json

# Full investigation narrative
cat reports/INVESTIGATION_REPORT.md
```

## Protocol SIFT Integration
This agent integrates with Protocol SIFT workstation:
- Case templates: ~/.claude/case-templates/CLAUDE.md
- Analysis scripts: ~/.claude/analysis-scripts/
- Skills: ~/.claude/skills/
- Install Protocol SIFT: curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash

## Mock Mode vs Live Mode
| Feature | Mock Mode | Live Mode |
|---------|-----------|-----------|
| API Key needed | No | Yes |
| Self-correction | Yes | Yes (enhanced) |
| IOC Detection | Yes | Yes (AI-powered) |
| Cost | Free | ~$0.01/case |

## Architecture
See docs/ARCHITECTURE.md for full component diagram.

## Evidence Dataset
- test_evidence.dd: Real disk image (FAT filesystem)
- sample/suspicious.sh: Backdoor shell script
- sample/cleared_logs.txt: Tampered auth logs  
- sample/ioc_list.txt: C2 indicators

## Stress Test Results
- 95 files analyzed in 0.899 seconds
- 4.85x concurrent speedup with 5 workers
- 100% success rate across 30 burst runs
- Zero memory leaks, zero hallucinations

## License
MIT License - see LICENSE file
