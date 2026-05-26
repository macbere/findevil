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
