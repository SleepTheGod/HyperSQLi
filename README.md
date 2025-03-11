# HyperSQLi
Here’s a GitHub README in cleartext format for your repository at https://github.com/SleepTheGod/HyperSQLi/ with the main code file named main.py. No Markdown, no colons, just plain text.

# HyperSQLi
High-speed SQLi scanner for pentesters. Crawls Google with dorks, tests URLs for vulnerabilities using multi-threading (50 threads), proxy rotation, and User-Agent spoofing from useragents.txt. Fast (0.1-0.5s delays), smart detection, JSON output. For authorized use only.

# About
This is HyperSQLi, a high-speed SQL injection vulnerability scanner built for penetration testers. It uses Google dorks to find potential targets, then tests them for SQLi vulnerabilities with 50 concurrent threads, proxy rotation, and User-Agent spoofing from a useragents.txt file. It’s designed to be fast with delays between 0.1 and 0.5 seconds, includes smart detection of vulnerabilities, and saves results in JSON format. This tool is for authorized security testing only.

# Repository
https://github.com/SleepTheGod/HyperSQLi/

# Installation
To install, run the following command to get the required dependencies
pip install -r requirements.txt

# Usage
To run HyperSQLi, use this command with your dork and proxy files
python3 main.py dorks.txt proxies.txt

# Files
main.py - The main script for HyperSQLi
dorks.txt - List of Google dorks to search for targets
proxies.txt - List of proxies in host port format (e.g., 192.168.1.1 1080)
useragents.txt - List of User-Agents for spoofing
requirements.txt - List of Python dependencies

# Requirements
Python 3.x
pysocks (optional for proxy support)

# How to Use
Clone the repository git clone https://github.com/SleepTheGod/HyperSQLi/
Navigate to the directory cd HyperSQLi
Install dependencies pip install -r requirements.txt
Prepare your dorks.txt, proxies.txt, and useragents.txt files
Run the scanner python3 main.py dorks.txt proxies.txt

# Output
Results are saved in the sqli_scan_results directory as JSON files with timestamps, containing vulnerable URLs and any errors encountered.

# Legal Notice
HyperSQLi is intended for authorized security testing only. Unauthorized use against systems without explicit permission may violate laws such as the Computer Fraud and Abuse Act (CFAA) or local regulations. Always obtain consent before scanning any target.

# Author
Taylor Christian Newsome
