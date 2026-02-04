# Security Log Analyzer

**Author:** Ushal Koirala
**Date:** 10/01/2026
**Version:** PC:01

## Overview
This python program reads server log files and identifies suspicious activity such as:
- Multiple failed login attempts from the same IP address.
- Access to restricted pages like `/admin` or `/config`.
- Brute-force attempts (many failed logins in a short time).

## How to Use
1. Place log files (`logs.txt`) in the same folder as the program.
2. Make sure `rules.json` in the folder.
3. Install required libraries:
    py -m pip install pandas matplotlib requests openpyxl
4. Open a terminal and run:
py SecurityLogAnalyzer.py --log logs.txt