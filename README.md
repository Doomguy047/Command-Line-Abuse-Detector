# Command-Line Abuse Detector

## Overview
A rule-based Python tool that inspects Windows process command-line logs to detect suspicious execution patterns associated with living-off-the-land abuse.


## Approach
- Parses process execution logs
- Applies rule-based detection logic to command-line arguments
- Flags suspicious usage patterns with contextual explanations

## Usage
```bash
python3 detector.py
