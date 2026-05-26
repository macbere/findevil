# FindEvil Agent Architecture
┌─────────────────────────────────────────────────────┐
│                 FINDEVIL AGENT                      │
│                                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐      │
│  │ Evidence │───▶│  Agent   │───▶│  SIFT    │      │
│  │  Input   │    │  Brain   │    │  Tools   │      │
│  └──────────┘    └────┬─────┘    └────┬─────┘      │
│                       │               │             │
│                  ┌────▼─────┐    ┌────▼─────┐      │
│                  │  Self-   │    │ Findings │      │
│                  │Correction│    │  Store   │      │
│                  └────┬─────┘    └────┬─────┘      │
│                       │               │             │
│                  ┌────▼───────────────▼─────┐      │
│                  │    Audit Trail / Logs     │      │
│                  └──────────────────────────┘      │
└─────────────────────────────────────────────────────┘
EVIDENCE FLOW:
disk.dd ──▶ fls/sleuthkit ──▶ file listing
──▶ foremost      ──▶ carved files
──▶ exiftool      ──▶ metadata
──▶ md5sum        ──▶ hash verify
──▶ volatility3   ──▶ memory analysis
──▶ yara          ──▶ pattern match
SELF-CORRECTION LOOP:
Finding ──▶ Validate ──▶ Pass? ──▶ Save
──▶ Fail? ──▶ Retry ──▶ Log
