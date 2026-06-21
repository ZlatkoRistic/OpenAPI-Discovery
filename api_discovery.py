#!/usr/bin/env python3
"""
Unified API Discovery and Fuzzing Tool
Combines black-box fuzzing capabilities with endpoint extraction and analysis
"""

import os
import re
import json
import sys
import subprocess
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Set, Tuple, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode
from collections import defaultdict


class KatanaCrawler:
    """
    Wraps the Katana CLI crawler (https://github.com/projectdiscovery/katana).

    Katana runs a real headless Chromium session, executes JavaScript, follows
    SPA routing, intercepts XHR/fetch calls, and submits forms — things a regex
    over static HTML/JS can never do.

    Output is parsed from Katana's JSONL format (-json flag) so every field
    (method, endpoint, body, source, form fields) is available to the rest of
    the pipeline.

    Modes
    -----
    standard  : fast Go HTTP client, no JS execution (like curl-based crawl)
    headless  : full Chromium — finds dynamically-built endpoints, SPA routes,
                click-triggered XHR.  Requires Chrome/Chromium installed.
    """

    def __init__(self, target_url: str, output_dir: str = './katana_results',
                 headless: bool = False, depth: int = 5, concurrency: int = 20,
                 timeout: int = 15, match_codes: str = '200,201,401,403',
                 follow_redirects: bool = True, extra_headers: Optional[Dict] = None,
                 cookie: Optional[str] = None):
        self.target_url     = target_url.rstrip('/')
        self.output_dir     = output_dir
        self.headless       = headless
        self.depth          = depth
        self.concurrency    = concurrency
        self.timeout        = timeout
        self.match_codes    = match_codes
        self.follow_redirects = follow_redirects
        self.extra_headers  = extra_headers or {}
        self.cookie         = cookie

        self._discovered: Dict[str, Set[str]] = {}   # path → methods
        self._form_params:  Dict[str, Dict]   = {}   # path → {method → {field: type}}
        self._xhr_bodies:   Dict[str, str]    = {}   # path → raw body seen in XHR

        os.makedirs(self.output_dir, exist_ok=True)

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    @staticmethod
    def is_installed() -> bool:
        try:
            subprocess.run(['katana', '-version'], capture_output=True, check=True)
            return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            return False

    def crawl(self) -> Dict[str, Set[str]]:
        """
        Run Katana and return ``{path: {methods}}`` dict.

        Also populates ``self._form_params`` and ``self._xhr_bodies`` for
        downstream parameter discovery.
        """
        if not self.is_installed():
            print("  [katana] NOT installed — skipping crawl.  "
                  "Install: go install github.com/projectdiscovery/katana/cmd/katana@latest")
            return {}

        out_file = os.path.join(self.output_dir, 'katana_output.jsonl')
        cmd = self._build_command(out_file)

        print(f"\n{'─'*80}")
        print(f"KATANA {'HEADLESS ' if self.headless else ''}CRAWL")
        print(f"{'─'*80}")
        print(f"  Target : {self.target_url}")
        print(f"  Depth  : {self.depth}   Concurrency: {self.concurrency}")
        print(f"  Mode   : {'headless (Chromium)' if self.headless else 'standard (Go HTTP)'}")
        print(f"  Cmd    : {' '.join(cmd)}\n")

        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as e:
            print(f"  [katana] Crawl failed: {e}")
            return {}
        except FileNotFoundError:
            print("  [katana] Binary not found in PATH")
            return {}

        return self._parse_output(out_file)

    def get_form_params(self) -> Dict[str, Dict]:
        """Return form field data extracted from the crawl."""
        return self._form_params

    def get_xhr_bodies(self) -> Dict[str, str]:
        """Return raw XHR request bodies seen during the crawl."""
        return self._xhr_bodies

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _build_command(self, out_file: str) -> List[str]:
        cmd = [
            'katana',
            '-u',        self.target_url,
            '-d',        str(self.depth),
            '-c',        str(self.concurrency),
            '-timeout',  str(self.timeout),
            '-o',        out_file,
            '-json',                   # JSONL output — one record per request
            '-jc',                     # JS crawling (parse JS files for URLs)
            '-xhr',                    # Capture XHR/fetch calls
            '-kf',       'robotstxt,sitemapxml',   # seed from robots.txt / sitemap
            '-aff',                    # automatic form filling
            '-fx',                     # extract form fields into output
            '-silent',                 # suppress banner
        ]

        if self.headless:
            cmd += ['-headless', '-hl']

        if not self.follow_redirects:
            cmd.append('-nr')

        for key, value in self.extra_headers.items():
            cmd += ['-H', f'{key}: {value}']

        if self.cookie:
            cmd += ['-H', f'Cookie: {self.cookie}']

        return cmd

    def _parse_output(self, out_file: str) -> Dict[str, Set[str]]:
        """Parse Katana JSONL output into ``{path: {methods}}``."""
        if not os.path.exists(out_file):
            print("  [katana] Output file not found — crawl may have produced no results")
            return {}

        parsed = 0
        skipped = 0

        with open(out_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue

                # Katana JSONL has a 'request' sub-object
                req = record.get('request', record)  # fallback: top-level
                endpoint_url = req.get('endpoint') or req.get('url', '')
                method       = (req.get('method') or 'GET').upper()
                body         = req.get('body', '')
                form_fields  = req.get('form', {})     # populated by -fx
                status       = (record.get('response') or {}).get('status_code', 0)

                if not endpoint_url:
                    skipped += 1
                    continue

                # Filter by match codes
                match_set = {int(c) for c in self.match_codes.split(',') if c.strip().isdigit()}
                if status and match_set and status not in match_set:
                    skipped += 1
                    continue

                path = self._url_to_path(endpoint_url)
                if not path:
                    skipped += 1
                    continue

                # Accumulate
                if path not in self._discovered:
                    self._discovered[path] = set()
                self._discovered[path].add(method)

                # Store form fields for parameter inference
                if form_fields:
                    self._form_params.setdefault(path, {})
                    self._form_params[path][method] = form_fields

                # Store XHR body
                if body and method in ('POST', 'PUT', 'PATCH'):
                    self._xhr_bodies[path] = body

                parsed += 1

        print(f"  [katana] Parsed {parsed} records, skipped {skipped}")
        print(f"  [katana] Discovered {len(self._discovered)} unique paths")
        return dict(self._discovered)

    def _url_to_path(self, url: str) -> Optional[str]:
        """Convert a full URL to a relative path, filtering out external URLs."""
        try:
            parsed = urlparse(url)
            base   = urlparse(self.target_url)
            # Drop external URLs
            if parsed.netloc and parsed.netloc != base.netloc:
                return None
            path = parsed.path.lstrip('/')
            # Re-attach query string if present (useful for GET param discovery)
            if parsed.query:
                path = f"{path}?{parsed.query}"
            return path or None
        except Exception:
            return None


class APIFuzzer:
    """Handles fuzzing of REST API endpoints"""
    
    def __init__(self, target_url: str, wordlist: str, output_dir: str = "./fuzzing_results",
                 follow_redirects: bool = True, match_codes: str = "200,201,401,403"):
        """
        Initialize the fuzzer
        
        Args:
            target_url: Target API URL (e.g., http://127.0.0.1:5000)
            wordlist: Path to wordlist file for fuzzing
            output_dir: Directory to store fuzzing results
            follow_redirects: Follow HTTP redirects
            match_codes: Comma-separated status codes to match (e.g., "200,201,401,403")
        """
        self.target_url = target_url.rstrip('/')
        self.wordlist = wordlist
        self.output_dir = output_dir
        self.follow_redirects = follow_redirects
        self.match_codes = match_codes
        self.endpoints_with_methods = {}
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def check_ffuf_installed(self) -> bool:
        """Check if ffuf is installed"""
        try:
            subprocess.run(['which', 'ffuf'], check=True, capture_output=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def fuzz_with_method(self, method: str = "GET", threads: int = 40, timeout: int = 10, 
                         output_filename: str = None) -> bool:
        """
        Fuzz the API using ffuf with a specific HTTP method
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
            threads: Number of fuzzing threads
            timeout: Timeout in seconds
            output_filename: Name of the output JSON file
        
        Returns:
            True if successful, False otherwise
        """
        if output_filename is None:
            output_filename = f"ffuf_results_{method.lower()}.json"
        
        print(f"\n{'='*70}")
        print(f"STARTING FFUF FUZZING WITH {method}")
        print(f"{'='*70}")
        print(f"Target: {self.target_url}")
        print(f"Method: {method}")
        print(f"Wordlist: {self.wordlist}")
        
        if not os.path.exists(self.wordlist):
            print(f"Error: Wordlist file {self.wordlist} not found")
            return False
        
        fuzz_url = f"{self.target_url}/FUZZ"
        
        cmd = [
            'ffuf',
            '-X', method,
            '-w', self.wordlist,
            '-u', fuzz_url,
            '-o', os.path.join(self.output_dir, output_filename),
            '-of', 'json',
            '-t', str(threads),
            '-timeout', str(timeout),
            '-mc', self.match_codes,
            '-od', self.output_dir
        ]
        
        if self.follow_redirects:
            cmd.insert(1, '-r')
        
        try:
            print(f"\nRunning: {' '.join(cmd)}\n")
            result = subprocess.run(cmd, check=True)
            print(f"\nFFUF completed successfully. Results saved to {self.output_dir}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error running ffuf: {e}")
            return False
        except FileNotFoundError:
            print("Error: ffuf not found")
            return False
    
    def fuzz_with_methods(self, methods: List[str] = None, threads: int = 40,
                         timeout: int = 10, parallel: bool = True) -> Dict[str, Dict[str, Set[str]]]:
        """
        Fuzz with multiple HTTP methods.

        Each method spawns its own independent ffuf process. By default these
        run CONCURRENTLY (one OS process per method) rather than sequentially —
        4 methods running in parallel finishes in roughly the time of the
        slowest single method instead of the sum of all four.

        Per-process thread count is divided by the number of methods so the
        total concurrent connection count against the target stays close to
        what a single sequential run would have used. Pass parallel=False to
        revert to one-at-a-time execution (gentler on fragile targets).

        Args:
            methods: List of HTTP methods to fuzz with
            threads: Total ffuf thread budget across all methods
            timeout: Timeout in seconds
            parallel: Run methods concurrently (default True)

        Returns:
            Dictionary mapping methods to their discovered endpoints
        """
        if methods is None:
            methods = ['GET', 'POST']

        all_results = {}

        if not parallel or len(methods) == 1:
            for method in methods:
                output_file = f"ffuf_results_{method.lower()}.json"
                success = self.fuzz_with_method(method, threads, timeout, output_file)
                if success:
                    all_results[method] = self.extract_endpoints_from_ffuf_results(
                        os.path.join(self.output_dir, output_file), method=method
                    )
            return all_results

        # Divide the thread budget so total concurrency ≈ a single-method run
        per_method_threads = max(5, threads // len(methods))

        def _run_one(method: str):
            output_file = f"ffuf_results_{method.lower()}.json"
            success = self.fuzz_with_method(method, per_method_threads, timeout, output_file)
            if not success:
                return method, {}
            return method, self.extract_endpoints_from_ffuf_results(
                os.path.join(self.output_dir, output_file), method=method
            )

        print(f"  Running {len(methods)} ffuf processes concurrently "
              f"({per_method_threads} threads each)…")
        with ThreadPoolExecutor(max_workers=len(methods)) as pool:
            futures = [pool.submit(_run_one, m) for m in methods]
            for future in as_completed(futures):
                method, endpoints = future.result()
                if endpoints:
                    all_results[method] = endpoints

        return all_results

    def fuzz_with_ffuf(self, threads: int = 40, timeout: int = 10,
                       output_filename: str = "ffuf_results.json") -> bool:
        """Alias for fuzz_with_method(GET) — keeps legacy callers working."""
        return self.fuzz_with_method('GET', threads, timeout, output_filename)

    def fuzz_parameters(self, endpoint: str, param_wordlist: str,
                        method: str = 'GET', threads: int = 40,
                        timeout: int = 10) -> Dict[str, Set[str]]:
        """
        Fuzz query/body parameter names on a discovered endpoint.

        Runs ``ffuf -u URL?FUZZ=test`` (or POST body ``FUZZ=test``) to find
        which parameter names elicit a distinct response.

        Returns a dict mapping the endpoint to a set of discovered param names,
        or an empty dict when nothing was found.
        """
        if not os.path.exists(param_wordlist):
            print(f"  [param-fuzz] Wordlist not found: {param_wordlist}")
            return {}

        # For GET use query string; for POST/PUT/PATCH use body data
        if method.upper() == 'GET':
            fuzz_url = f"{self.target_url}/{endpoint.lstrip('/')}?FUZZ=test"
            extra_args: List[str] = []
        else:
            fuzz_url = f"{self.target_url}/{endpoint.lstrip('/')}"
            extra_args = ['-d', 'FUZZ=test',
                          '-H', 'Content-Type: application/x-www-form-urlencoded']

        output_file = os.path.join(
            self.output_dir,
            f"params_{method.lower()}_{re.sub(r'[^a-zA-Z0-9]', '_', endpoint)}.json"
        )

        cmd = [
            'ffuf',
            '-X', method,
            '-w', param_wordlist,
            '-u', fuzz_url,
            '-o', output_file,
            '-of', 'json',
            '-t', str(threads),
            '-timeout', str(timeout),
            '-mc', self.match_codes,
        ] + extra_args

        if self.follow_redirects:
            cmd.insert(1, '-r')

        try:
            print(f"  [param-fuzz] {method} /{endpoint.lstrip('/')} ...")
            subprocess.run(cmd, check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            return {}

        params: Set[str] = set()
        if os.path.exists(output_file):
            try:
                with open(output_file) as f:
                    data = json.load(f)
                for r in data.get('results', []):
                    raw = r.get('input', {}).get('FUZZ', '')
                    if isinstance(raw, (bytes, bytearray)):
                        raw = raw.decode()
                    if raw:
                        params.add(str(raw))
            except (json.JSONDecodeError, KeyError):
                pass

        if params:
            print(f"  [param-fuzz] Found {len(params)} params: {', '.join(sorted(params))}")
        return {endpoint: params} if params else {}

    def extract_endpoints_from_ffuf_results(self, results_file: str = None, method: str = 'GET') -> Dict[str, Set[str]]:
        """
        Extract endpoints from ffuf JSON results
        
        Args:
            results_file: Path to ffuf results JSON file
            method: HTTP method used in this fuzzing run
        
        Returns:
            Dictionary of endpoints with their HTTP methods
        """
        if results_file is None:
            results_file = os.path.join(self.output_dir, 'ffuf_results.json')
        
        if not os.path.exists(results_file):
            print(f"Results file {results_file} not found")
            return {}
        
        endpoints = {}
        
        try:
            with open(results_file, 'r') as f:
                data = json.load(f)
            
            results = data.get('results', [])
            for result in results:
                url = result.get('url', '')
                # Extract the path from the full URL
                parsed = urlparse(url)
                endpoint = parsed.path
                
                if endpoint.startswith('/'):
                    endpoint = endpoint[1:]
                
                # Use the method that was used for this fuzzing run
                if endpoint not in endpoints:
                    endpoints[endpoint] = set()
                endpoints[endpoint].add(method)
            
            print(f"\nExtracted {len(endpoints)} endpoints from ffuf results (method: {method})")
            return endpoints
        
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON results: {e}")
            return {}
        except Exception as e:
            print(f"Error extracting endpoints: {e}")
            return {}


class EndpointExtractor:
    """Handles extraction of endpoints from various file types"""
    
    @staticmethod
    def open_file(filepath: str) -> str:
        """Open and read file contents"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as file:
                return file.read()
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
            return ""
    
    @staticmethod
    def extract_from_http_request(content: str) -> Tuple[str, str]:
        """
        Extract HTTP method and endpoint from HTTP request line
        
        Args:
            content: HTTP request content
        
        Returns:
            Tuple of (endpoint, method)
        """
        first_line = content.split('\n')[0].strip()
        # Pattern: METHOD /endpoint HTTP/VERSION
        match = re.match(r'(\w+)\s+(/[^\s]*)\s+HTTP', first_line)
        
        if match:
            method = match.group(1)
            endpoint = match.group(2)
            
            if endpoint.startswith('/'):
                endpoint = endpoint[1:]
            
            return endpoint, method
        
        return None, None
    
    @staticmethod
    def extract_ajax_endpoints(content: str) -> Dict[str, Set[str]]:
        """
        Extract endpoints and HTTP methods from AJAX calls
        
        Args:
            content: HTML/JavaScript content
        
        Returns:
            Dictionary of endpoints with their HTTP methods
        """
        endpoints = {}
        
        # Find $.ajax() calls
        ajax_pattern = r'\$\.ajax\s*\(\s*\{([^}]+)\}'
        ajax_blocks = re.findall(ajax_pattern, content)
        
        for block in ajax_blocks:
            url_match = re.search(r'url\s*:\s*["\']([^"\']+)["\']', block)
            method_match = re.search(r'(?:type|method)\s*:\s*["\'](\w+)["\']', block)
            
            if url_match:
                endpoint = url_match.group(1)
                if endpoint.startswith('/'):
                    endpoint = endpoint[1:]
                
                method = method_match.group(1).upper() if method_match else "GET"
                
                if endpoint not in endpoints:
                    endpoints[endpoint] = set()
                endpoints[endpoint].add(method)
        
        # Find fetch() calls
        fetch_pattern = r'fetch\s*\(\s*["\']([^"\']+)["\'](?:\s*,\s*\{([^}]*)\})?'
        fetch_calls = re.findall(fetch_pattern, content)
        
        for endpoint, options in fetch_calls:
            if endpoint.startswith('/'):
                endpoint = endpoint[1:]
            
            method = "GET"
            if options:
                method_match = re.search(r'method\s*:\s*["\'](\w+)["\']', options)
                if method_match:
                    method = method_match.group(1).upper()
            
            if endpoint not in endpoints:
                endpoints[endpoint] = set()
            endpoints[endpoint].add(method)
        
        return endpoints
    
    @staticmethod
    def extract_parameters_from_endpoint(endpoint: str) -> List[str]:
        """
        Extract parameters from endpoint path
        
        Args:
            endpoint: Endpoint path
        
        Returns:
            List of parameters
        """
        # Look for patterns like {id}, :id, [id], etc.
        patterns = [
            r'\{([^}]+)\}',      # {id}
            r':([a-zA-Z_]\w*)',   # :id
            r'\[([^\]]+)\]',      # [id]
            r'<([^>]+)>',         # <id>
        ]
        
        parameters = []
        for pattern in patterns:
            matches = re.findall(pattern, endpoint)
            parameters.extend(matches)
        
        return list(set(parameters))
    
    @staticmethod
    def extract_query_parameters(url: str) -> List[Tuple[str, str]]:
        """
        Extract query parameters from URL
        
        Args:
            url: Full URL
        
        Returns:
            List of (parameter, value) tuples
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        return [(k, v[0] if v else "") for k, v in params.items()]


class ChainedFuzzingWorkflow:
    """Handles chained fuzzing workflow across multiple wordlists and discovered endpoints"""
    
    def __init__(self, target_url: str, output_dir: str = "./fuzzing_results",
                 follow_redirects: bool = True, match_codes: str = "200,201,401,403"):
        self.target_url = target_url.rstrip('/')
        self.output_dir = output_dir
        self.follow_redirects = follow_redirects
        self.match_codes = match_codes
        self.discovered_endpoints = {}  # endpoint -> methods
        self.wordlist_results = {}  # wordlist -> endpoints
        self.all_fuzzing_data = {}  # Aggregated data
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def fuzz_wordlist_chain(self, wordlists: List[str], methods: List[str] = None,
                           threads: int = 40, timeout: int = 10, 
                           recursive_depth: int = 1) -> Dict:
        """
        Execute chained fuzzing workflow:
        1. Fuzz with wordlist 1 using GET/POST
        2. Extract discovered endpoints
        3. Use discovered endpoints as base paths for wordlist 2
        4. Repeat for each wordlist
        
        Args:
            wordlists: List of wordlist file paths
            methods: HTTP methods to fuzz with (default: GET, POST)
            threads: Number of fuzzing threads
            timeout: Timeout in seconds
            recursive_depth: How many levels deep to fuzz discovered endpoints
        
        Returns:
            Dictionary with all results and statistics
        """
        if methods is None:
            methods = ['GET', 'POST']
        
        print(f"\n{'='*80}")
        print("STARTING CHAINED FUZZING WORKFLOW")
        print(f"{'='*80}")
        print(f"Target: {self.target_url}")
        print(f"Wordlists: {len(wordlists)}")
        print(f"Methods: {methods}")
        print(f"Recursive depth: {recursive_depth}")
        
        # First pass: fuzz with each wordlist at root
        base_endpoints = {}
        for idx, wordlist in enumerate(wordlists, 1):
            print(f"\n{'─'*80}")
            print(f"PHASE {idx}: Fuzzing with wordlist - {os.path.basename(wordlist)}")
            print(f"{'─'*80}")
            
            fuzzer = APIFuzzer(
                self.target_url,
                wordlist,
                output_dir=self.output_dir,
                follow_redirects=self.follow_redirects,
                match_codes=self.match_codes
            )
            
            # Fuzz with multiple methods
            method_results = fuzzer.fuzz_with_methods(methods, threads, timeout)
            
            # Aggregate results
            for method, endpoints in method_results.items():
                for endpoint, eps_methods in endpoints.items():
                    if endpoint not in base_endpoints:
                        base_endpoints[endpoint] = set()
                    base_endpoints[endpoint].update(eps_methods)
            
            self.wordlist_results[os.path.basename(wordlist)] = base_endpoints.copy()
            self.discovered_endpoints.update(base_endpoints)
            
            print(f"Phase {idx} discovered {len(base_endpoints)} unique endpoints")
        
        # Recursive fuzzing: use discovered endpoints as base paths
        if recursive_depth > 1:
            print(f"\n{'='*80}")
            print(f"RECURSIVE FUZZING: Using discovered endpoints as base paths")
            print(f"{'='*80}")
            
            for depth in range(2, recursive_depth + 1):
                new_endpoints = {}
                
                for base_endpoint in sorted(base_endpoints.keys()):
                    # Skip endpoints that look like files
                    if any(base_endpoint.endswith(ext) for ext in 
                           ['.js', '.css', '.html', '.json', '.txt', '.xml']):
                        continue
                    
                    # Fuzz the discovered endpoint with first wordlist as sub-fuzz
                    print(f"\nDepth {depth}: Fuzzing {base_endpoint}/ with first wordlist")
                    
                    fuzzer = APIFuzzer(
                        f"{self.target_url}/{base_endpoint}",
                        wordlists[0],  # Use first wordlist for recursive fuzzing
                        output_dir=os.path.join(self.output_dir, f"depth_{depth}"),
                        follow_redirects=self.follow_redirects,
                        match_codes=self.match_codes
                    )
                    
                    # Quick fuzz with just GET
                    success = fuzzer.fuzz_with_ffuf(threads, timeout, 
                                                   output_filename=f"recursive_{base_endpoint.replace('/', '_')}.json")
                    
                    if success:
                        endpoints = fuzzer.extract_endpoints_from_ffuf_results()
                        # Prepend base path
                        for ep in endpoints:
                            full_ep = f"{base_endpoint}/{ep}"
                            if full_ep not in new_endpoints:
                                new_endpoints[full_ep] = set()
                            new_endpoints[full_ep].update(endpoints[ep])
                
                base_endpoints.update(new_endpoints)
                self.discovered_endpoints.update(new_endpoints)
                print(f"Depth {depth} found {len(new_endpoints)} new endpoints")
        
        # Save summary
        self._save_workflow_summary(base_endpoints)
        
        return {
            'total_endpoints': len(self.discovered_endpoints),
            'endpoints': self.discovered_endpoints,
            'wordlist_results': self.wordlist_results
        }
    
    def _save_workflow_summary(self, endpoints: Dict[str, Set[str]]):
        """Save workflow summary to file"""
        summary_file = os.path.join(self.output_dir, 'chained_fuzzing_summary.txt')
        
        with open(summary_file, 'w') as f:
            f.write("CHAINED FUZZING WORKFLOW SUMMARY\n")
            f.write(f"{'='*80}\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Total unique endpoints: {len(endpoints)}\n\n")
            
            f.write(f"{'Endpoint':<50} {'Methods'}\n")
            f.write(f"{'-'*80}\n")
            
            for endpoint in sorted(endpoints.keys()):
                methods = ', '.join(sorted(endpoints[endpoint]))
                f.write(f"{endpoint:<50} {methods}\n")
        
        print(f"\nWorkflow summary saved to: {summary_file}")


class ResponseParser:
    """Parses HTTP responses to extract new endpoint references"""
    
    @staticmethod
    def fetch_endpoint(url: str, method: str = 'GET', timeout: int = 10,
                       retries: int = 2, backoff: float = 1.5) -> Tuple[Optional[int], Optional[str]]:
        """
        Fetch an endpoint and return (status_code, content).

        Retries up to *retries* times on connection errors or timeouts,
        doubling the wait (backoff) between each attempt.  Returns
        (None, None) only after all retries are exhausted.
        """
        try:
            import requests
            from requests.exceptions import Timeout, ConnectionError as ReqConnErr
        except ImportError:
            print("ERROR: requests library not installed. Install with: pip3 install requests")
            return None, None

        attempt = 0
        wait = backoff
        while attempt <= retries:
            try:
                response = requests.request(
                    method.upper(), url,
                    timeout=timeout,
                    allow_redirects=True,
                    verify=False
                )
                return response.status_code, response.text
            except (Timeout, ReqConnErr) as exc:
                attempt += 1
                if attempt > retries:
                    return None, None
                time.sleep(wait)
                wait *= 2
            except Exception:
                return None, None
        return None, None
    
    @staticmethod
    def extract_endpoints_from_response(content: str, base_url: str) -> Set[str]:
        """
        Extract endpoint references from HTML/JS content
        
        Args:
            content: Response content
            base_url: Base URL for context
        
        Returns:
            Set of discovered endpoints
        """
        endpoints = set()
        
        # Parse base URL to get domain
        parsed = urlparse(base_url)
        domain = f"{parsed.scheme}://{parsed.netloc}"
        
        # Pattern 1: Fetch calls: fetch("/endpoint", ...)
        fetch_pattern = r'fetch\(["\']([^"\']+)["\']'
        fetches = re.findall(fetch_pattern, content)
        for fetch in fetches:
            if fetch.startswith('/'):
                fetch = fetch[1:]
            endpoints.add(fetch)
        
        # Pattern 2: AJAX calls: url: "/endpoint"
        ajax_url_pattern = r'(?:url|endpoint|api|path)\s*:\s*["\']([^"\']+)["\']'
        ajax_urls = re.findall(ajax_url_pattern, content)
        for url in ajax_urls:
            if url.startswith('/'):
                url = url[1:]
            if not url.startswith('http'):  # Skip full URLs
                endpoints.add(url)
        
        # Pattern 3: API endpoint patterns in code
        api_pattern = r'["\'](?:/api/|/v\d+/|/service/)([a-zA-Z0-9_\-/]+)["\']'
        apis = re.findall(api_pattern, content)
        for api in apis:
            endpoints.add(api)
        
        # Pattern 4: Route/endpoint definitions
        route_pattern = r'(?:route|endpoint|path|url)\s*=\s*["\']([^"\']+)["\']'
        routes = re.findall(route_pattern, content)
        for route in routes:
            if route.startswith('/'):
                route = route[1:]
            endpoints.add(route)

        # Pattern 5: Jinja2/Flask url_for() calls in HTML templates
        # e.g. url_for('home.homepage')  url_for("projects.my_projects", employee=...)
        # The blueprint.endpoint name maps directly to a routable URL path.
        # We extract the endpoint name and convert it:
        #   'home.homepage'        -> 'home/homepage'  (probe both forms)
        #   'projects.my_projects' -> 'projects/my_projects' and 'my-projects'
        for raw in re.findall(r"""url_for\s*\(\s*['"]([^'"]+)['"]""", content):
            # raw = 'blueprint.endpoint_name' or just 'endpoint_name'
            raw = raw.strip()
            if '.' in raw:
                blueprint, ep_name = raw.split('.', 1)
                # Try slash-joined:  projects/my_projects
                endpoints.add(f"{blueprint}/{ep_name}")
                # Try blueprint as prefix with hyphenated endpoint:
                #   projects/my-projects
                endpoints.add(f"{blueprint}/{ep_name.replace('_', '-')}")
                # Try just the endpoint name alone (some Flask apps mount at root):
                endpoints.add(ep_name)
                endpoints.add(ep_name.replace('_', '-'))
            else:
                endpoints.add(raw)
                endpoints.add(raw.replace('_', '-'))

        # Pattern 6: Twig / Django / generic template engine route() / path() calls
        # e.g. {{ path('app_home') }}   route('user_profile', {id: 1})
        for raw in re.findall(r"""(?:path|route|url)\s*\(\s*['"]([a-zA-Z0-9_\-]+)['"]""", content):
            endpoints.add(raw)
            endpoints.add(raw.replace('_', '-'))
        
        # Clean up endpoints
        cleaned = set()
        # List of file extensions to exclude
        file_extensions = [
            '.js', '.css', '.json', '.map', '.woff', '.woff2', '.ttf', '.eot',
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz',
            '.mp3', '.mp4', '.mov', '.avi', '.flv', '.wmv', '.wav',
            '.txt', '.csv', '.xml', '.html', '.htm'
        ]
        
        for ep in endpoints:
            # Remove query parameters
            if '?' in ep:
                ep = ep.split('?')[0]
            # Remove fragments
            if '#' in ep:
                ep = ep.split('#')[0]
            # Remove duplicate slashes
            ep = re.sub(r'/+', '/', ep)
            # Remove leading/trailing slashes
            ep = ep.strip('/')
            
            # Skip empty endpoints
            if not ep:
                continue
            
            # Skip file-based resources (exclude endpoints that are files)
            skip = False
            for ext in file_extensions:
                if ep.endswith(ext) or f"{ext}?" in ep:
                    skip = True
                    break
            
            if not skip:
                cleaned.add(ep)
        
        return cleaned
    
    @staticmethod
    def analyze_response_for_parameters(response_content: str, url: str, method: str = 'GET') -> Dict:
        """
        Analyze response to extract parameter information
        
        Args:
            response_content: HTTP response body
            url: The URL that was accessed
            method: HTTP method used
        
        Returns:
            Dict with discovered parameters by type (query, body, path, form)
        """
        params = {
            'query': {},
            'path': {},
            'body': {},
            'formData': {}
        }
        
        # Extract query parameters from request URL
        query_params = ParameterExtractor.extract_query_params_from_url(url)
        params['query'] = query_params
        
        # Extract path parameters from URL pattern
        path = urlparse(url).path
        if path:
            path_params = ParameterExtractor.extract_path_params_from_pattern(path)
            params['path'] = path_params
        
        # Try to extract JSON body parameters from response
        json_params = ParameterExtractor.extract_body_params_from_json(response_content)
        if json_params:
            params['body'] = json_params
        
        # Extract form fields if response contains HTML
        if '<form' in response_content or '<input' in response_content:
            form_params = ParameterExtractor.extract_form_fields_from_html(response_content)
            params['formData'] = form_params
        
        return params
    
    @staticmethod
    def extract_js_file_references(content: str, base_url: str) -> Set[str]:
        """
        Extract JavaScript file references from HTML content
        
        Args:
            content: HTML content
            base_url: Base URL for context
        
        Returns:
            Set of JavaScript file URLs
        """
        js_files = set()
        
        # Find <script src="..."> references
        script_src_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
        matches = re.findall(script_src_pattern, content)
        
        for match in matches:
            # Handle relative and absolute URLs
            if match.startswith('http'):
                js_files.add(match)
            elif match.startswith('/'):
                parsed = urlparse(base_url)
                js_files.add(f"{parsed.scheme}://{parsed.netloc}{match}")
            else:
                # Relative path
                parsed = urlparse(base_url)
                base_path = parsed.path.rstrip('/')
                js_files.add(f"{parsed.scheme}://{parsed.netloc}{base_path}/{match}")
        
        return js_files
    
    @staticmethod
    def analyze_javascript_file(js_url: str, timeout: int = 10) -> Set[str]:
        """
        Fetch and analyze a JavaScript file for API endpoint references.

        Covers:
        - fetch('/path') and fetch('path')  (with or without leading slash)
        - axios.get/post/put/delete/patch('path')
        - $.ajax / $.get / $.post with url: 'path'
        - XHR .open('GET', 'path')
        - Bare string literals that look like kebab-case, slash-separated,
          or /prefixed API paths — catches things like 'get-translation-dict'
          that are called without a leading slash
        """
        endpoints: Set[str] = set()

        try:
            import requests
            response = requests.get(js_url, timeout=timeout, verify=False)
            if response.status_code != 200:
                return endpoints
            content = response.text
        except Exception:
            return endpoints

        # CSS properties, HTML attributes, Bootstrap/ARIA prefixes and full names
        # that should never be mistaken for API endpoints.
        _BLOCKED_PREFIXES = (
            'aria-', 'data-', 'bs-', 'ng-', 'v-', 'x-',          # HTML/framework attrs
            'margin-', 'padding-', 'border-', 'outline-',          # CSS box model
            'background-', 'font-', 'text-', 'line-', 'list-',     # CSS typography/bg
            'flex-', 'grid-', 'align-', 'justify-', 'place-',      # CSS layout
            'overflow-', 'pointer-', 'cursor-', 'z-',              # CSS misc
            'transition-', 'animation-', 'transform-',             # CSS animation
            'min-', 'max-', 'col-', 'row-',                        # CSS sizing / Bootstrap grid
        )
        _BLOCKED_EXACT = {
            'form-control', 'form-group', 'form-check', 'form-select',
            'form-control-sm', 'form-control-lg',
            'input-group', 'input-group-text',
            'nav-link', 'nav-item', 'nav-bar', 'nav-tabs', 'nav-pills',
            'navbar-brand', 'navbar-toggler', 'navbar-collapse', 'navbar-nav',
            'btn-primary', 'btn-secondary', 'btn-success', 'btn-danger',
            'btn-warning', 'btn-info', 'btn-light', 'btn-dark', 'btn-link',
            'btn-sm', 'btn-lg', 'btn-group', 'btn-outline',
            'dropdown-menu', 'dropdown-item', 'dropdown-toggle', 'dropdown-divider',
            'list-group', 'list-group-item', 'list-inline', 'list-unstyled',
            'badge', 'alert', 'card', 'modal', 'tooltip', 'popover',
            'collapse', 'accordion', 'carousel', 'spinner', 'progress',
            'table-striped', 'table-bordered', 'table-hover', 'table-sm',
            'sr-only', 'visually-hidden', 'clearfix', 'float-start', 'float-end',
            'text-center', 'text-start', 'text-end', 'text-truncate',
            'opt-out', 'opt-in', 'filter-option', 'optgroup-label',
            'border-box', 'content-box',
        }

        def _clean(raw: str) -> Optional[str]:
            """Strip leading slash, reject non-endpoint strings."""
            raw = raw.strip().lstrip('/')
            if not raw:
                return None
            if raw.startswith(('http://', 'https://', '//', 'data:', 'blob:')):
                return None
            if re.search(r'\.(js|css|png|jpg|gif|svg|woff|ttf|ico|html|map)$', raw, re.I):
                return None
            if not re.search(r'[a-zA-Z]', raw):
                return None
            # Reject CSS/HTML attribute patterns
            lower = raw.lower()
            if any(lower.startswith(p) for p in _BLOCKED_PREFIXES):
                return None
            if lower in _BLOCKED_EXACT:
                return None
            return raw

        # Context keywords that indicate a string is being used as a network target.
        # Pattern 6 only fires on lines that contain one of these nearby.
        _NET_CONTEXT = re.compile(
            r'\b(?:fetch|axios|ajax|xhr|request|get|post|put|patch|delete|'
            r'url|endpoint|baseUrl|apiUrl|route|path|href|src|action|api)\b',
            re.I
        )

        # Pattern 1: fetch('...') and fetch("...")
        for raw in re.findall(r"""\bfetch\s*\(\s*['"`]([^'"`\s?#]{1,120})['"`]""", content):
            c = _clean(raw)
            if c:
                endpoints.add(c)

        # Pattern 2: axios.get/post/put/patch/delete('...')
        for raw in re.findall(
            r"""\baxios\s*\.\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*['"`]([^'"`\s?#]{1,120})['"`]""",
            content, re.I
        ):
            c = _clean(raw)
            if c:
                endpoints.add(c)

        # Pattern 3: $.ajax / $.get / $.post / $.getJSON / $.getScript
        for raw in re.findall(
            r"""\$\s*\.\s*(?:ajax|get|post|getJSON|getScript)\s*\(\s*['"`]([^'"`\s?#]{1,120})['"`]""",
            content, re.I
        ):
            c = _clean(raw)
            if c:
                endpoints.add(c)

        # Pattern 4: url/endpoint/api key in object literals
        for raw in re.findall(
            r"""\b(?:url|endpoint|api(?:Url|Endpoint)?|href|action|path|route)\s*[=:]\s*['"`]([^'"`\s?#]{1,120})['"`]""",
            content, re.I
        ):
            c = _clean(raw)
            if c:
                endpoints.add(c)

        # Pattern 5: XMLHttpRequest .open('METHOD', 'path')
        for raw in re.findall(
            r"""\.open\s*\(\s*['"](?:GET|POST|PUT|DELETE|PATCH|HEAD)['"]\s*,\s*['"`]([^'"`\s?#]{1,120})['"`]""",
            content, re.I
        ):
            c = _clean(raw)
            if c:
                endpoints.add(c)

        # Pattern 6: Kebab/slash string literals — ONLY on lines with a network context keyword.
        # This stops CSS class names, Bootstrap attrs, and ARIA values from matching
        # while still catching bare paths like  const URL = 'get-translation-dict'
        for line in content.splitlines():
            if not _NET_CONTEXT.search(line):
                continue
            for raw in re.findall(r"""['"`](/?[a-z][a-z0-9]*(?:[-/][a-z][a-z0-9]*){1,10})['"`]""", line):
                c = _clean(raw)
                if c:
                    endpoints.add(c)

        return endpoints

    @staticmethod
    def discover_endpoints_from_js_files(html_content: str, base_url: str,
                                          timeout: int = 10,
                                          max_workers: int = 10) -> Set[str]:
        """
        Concurrently fetch every <script src="…"> in *html_content* and mine
        API endpoint strings from them.

        Uses a thread-pool so a slow or hanging JS file does not block
        the rest of the scan.  Each worker respects *timeout* seconds.

        Returns:
            Set of discovered endpoint paths (no leading slash).
        """
        js_urls = ResponseParser.extract_js_file_references(html_content, base_url)
        if not js_urls:
            return set()

        all_endpoints: Set[str] = set()

        def _fetch_one(js_url: str) -> Set[str]:
            return ResponseParser.analyze_javascript_file(js_url, timeout)

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_fetch_one, u): u for u in js_urls}
            for future in as_completed(futures, timeout=timeout * 2):
                try:
                    result = future.result(timeout=1)
                    all_endpoints.update(result)
                except Exception:
                    pass

        return all_endpoints


class ParameterExtractor:
    """Extracts and analyzes request parameters according to OpenAPI specification"""
    
    def __init__(self):
        self.endpoints_params = {}  # endpoint -> {method -> {param_type -> [params]}}
    
    @staticmethod
    def infer_type_from_value(value) -> str:
        """Infer OpenAPI parameter type from value"""
        if isinstance(value, bool):
            return "boolean"
        elif isinstance(value, int):
            return "integer"
        elif isinstance(value, float):
            return "number"
        elif isinstance(value, str):
            if value.isdigit():
                return "integer"
            elif re.match(r'^\d{4}-\d{2}-\d{2}', value):
                return "string"  # ISO date format
            return "string"
        return "string"
    
    @staticmethod
    def extract_query_params_from_url(url: str) -> Dict[str, str]:
        """
        Extract query parameters from URL
        
        Returns:
            Dict of parameter name -> example value
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return {k: v[0] if v else "" for k, v in params.items()}
    
    @staticmethod
    def extract_path_params_from_pattern(endpoint: str) -> Dict[str, str]:
        """
        Extract path parameters from endpoint pattern
        
        Common patterns: {id}, :id, [id], <id>
        
        Returns:
            Dict of parameter name -> "string" (default type)
        """
        patterns = [
            r'\{([^}]+)\}',      # {id}
            r':([a-zA-Z_]\w*)',   # :id
            r'\[([^\]]+)\]',      # [id]
            r'<([^>]+)>',         # <id>
        ]
        
        params = {}
        for pattern in patterns:
            matches = re.findall(pattern, endpoint)
            for match in matches:
                params[match] = "string"  # Default to string type
        
        return params
    
    @staticmethod
    def extract_body_params_from_json(content: str) -> Dict[str, Dict]:
        """
        Extract potential request body parameters from JSON response
        Analyzes JSON structure to infer request schema
        
        Returns:
            Dict of parameter name -> {type, example, required}
        """
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                params = {}
                for key, value in data.items():
                    params[key] = {
                        "type": ParameterExtractor.infer_type_from_value(value),
                        "example": value,
                        "in": "body"
                    }
                return params
        except (json.JSONDecodeError, TypeError):
            pass
        
        return {}
    
    @staticmethod
    def extract_form_fields_from_html(content: str) -> Dict[str, Dict]:
        """
        Extract form fields from HTML content
        Helps identify POST/PUT body parameters
        
        Returns:
            Dict of parameter name -> {type, in: "formData"}
        """
        params = {}
        
        # Find form fields
        input_pattern = r'<input[^>]*name=["\']?([^"\'\s>]+)["\']?[^>]*type=["\']?([^"\'\s>]+)?'
        inputs = re.findall(input_pattern, content)
        for name, input_type in inputs:
            param_type = input_type if input_type else "text"
            params[name] = {
                "type": "string" if param_type in ["text", "password", "email"] else param_type,
                "in": "formData"
            }
        
        # Find textarea fields
        textarea_pattern = r'<textarea[^>]*name=["\']?([^"\'\s>]+)'
        textareas = re.findall(textarea_pattern, content)
        for name in textareas:
            params[name] = {"type": "string", "in": "formData"}
        
        # Find select fields
        select_pattern = r'<select[^>]*name=["\']?([^"\'\s>]+)'
        selects = re.findall(select_pattern, content)
        for name in selects:
            params[name] = {"type": "string", "in": "formData"}
        
        return params
    
    def add_endpoint_params(self, endpoint: str, method: str, param_type: str, params: Dict):
        """
        Track parameters for an endpoint-method combination
        
        Args:
            endpoint: The endpoint path
            method: HTTP method (GET, POST, etc.)
            param_type: Type of parameter (query, path, body, formData)
            params: Dictionary of parameters for this type
        """
        if endpoint not in self.endpoints_params:
            self.endpoints_params[endpoint] = {}
        
        if method not in self.endpoints_params[endpoint]:
            self.endpoints_params[endpoint][method] = {}
        
        if param_type not in self.endpoints_params[endpoint][method]:
            self.endpoints_params[endpoint][method][param_type] = {}
        
        self.endpoints_params[endpoint][method][param_type].update(params)
    
    def get_endpoint_parameters(self, endpoint: str, method: str) -> Dict:
        """Get all parameters for an endpoint-method combination"""
        if endpoint in self.endpoints_params and method in self.endpoints_params[endpoint]:
            return self.endpoints_params[endpoint][method]
        return {}


class PathParamProber:
    """
    Detects hidden path-parameter variants of discovered endpoints.

    For every endpoint that returns 404 (or was never probed), this class:
    1. Establishes a 404 *baseline* using a random suffix that cannot exist.
    2. Sends a small set of typed candidate values (integers, UUIDs, slugs).
    3. Compares each response against the baseline by status code AND body size.
    4. Infers the parameter type from whichever candidate first produced a hit.
    5. Returns normalised paths like ``users/{id}`` ready for OpenAPI output,
       along with the inferred schema so callers don't have to do the work twice.

    The class is intentionally stateless — construct one instance per scan run
    and call :py:meth:`probe_all` with your discovered endpoint dict.
    """

    # Candidate values grouped by inferred type.
    # Probed in order; the *first* hit determines the type for that endpoint.
    _CANDIDATES: List[Tuple[str, List[str]]] = [
        ("integer", ["1", "2", "10", "100", "9999"]),
        ("uuid",    [
            "00000000-0000-0000-0000-000000000001",
            "550e8400-e29b-41d4-a716-446655440000",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
        ]),
        ("slug",    ["me", "current", "self", "latest", "new", "default",
                     "profile", "settings", "admin", "test"]),
    ]

    # A probe value guaranteed to produce a 404 for any sane API.
    _NOISE_SUFFIX = "zz_nonexistent_probe_xk39q"

    # Body-size delta that constitutes a "real" response (not just whitespace).
    _SIZE_DELTA_THRESHOLD = 20

    def __init__(self, target_url: str, timeout: int = 10, retries: int = 2,
                 max_workers: int = 10):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.retries = retries
        self.max_workers = max_workers

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def probe_all(self, endpoints: Dict[str, Set[str]]) -> Dict[str, Dict]:
        """
        Probe every endpoint for path-parameter variants.

        Args:
            endpoints: ``{path: {methods}}`` dict from the fuzzer, e.g.
                       ``{"api/users": {"GET","POST"}, "api/items": {"GET"}}``

        Returns:
            A dict of *normalised* paths to discovery metadata::

                {
                    "api/users/{id}": {
                        "original_endpoint": "api/users",
                        "methods": {"GET", "POST"},
                        "param_name": "id",
                        "param_type": "integer",
                        "param_format": None,          # or "uuid"
                        "example_value": "1",
                        "hit_status": 200,
                    },
                    ...
                }

            Endpoints where no path-param variant was found are absent.
        """
        results: Dict[str, Dict] = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            future_to_ep = {
                pool.submit(self._probe_one, ep, methods): ep
                for ep, methods in endpoints.items()
                if not self._already_parametric(ep)
            }
            for future in as_completed(future_to_ep):
                ep = future_to_ep[future]
                try:
                    hit = future.result(timeout=self.timeout * 3)
                    if hit:
                        results[hit['normalised_path']] = hit
                except Exception:
                    pass

        if results:
            print(f"\n[path-param] Discovered {len(results)} parametric endpoint(s):")
            for path, meta in sorted(results.items()):
                print(f"  /{path}  ({meta['param_type']})  "
                      f"e.g. /{meta['original_endpoint']}/{meta['example_value']}")

        return results

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _already_parametric(self, endpoint: str) -> bool:
        """Return True if the path already contains a known placeholder."""
        return bool(re.search(r'\{[^}]+\}|:[a-zA-Z_]\w*|<[^>]+>', endpoint))

    def _fetch(self, url: str) -> Tuple[Optional[int], int]:
        """Fetch *url* and return (status_code, body_len).  None on error."""
        status, body = ResponseParser.fetch_endpoint(
            url, 'GET', self.timeout, self.retries
        )
        return status, len(body) if body else 0

    def _probe_one(self, endpoint: str, methods: Set[str]) -> Optional[Dict]:
        """
        Probe a single endpoint for a path-param variant.

        Returns a hit-dict on success or None if nothing found.
        """
        base_url = f"{self.target_url}/{endpoint.lstrip('/')}"

        # 1. Baseline — what does "not found" look like for this endpoint?
        baseline_status, baseline_size = self._fetch(
            f"{base_url}/{self._NOISE_SUFFIX}"
        )

        # If baseline itself is unreachable, skip.
        if baseline_status is None:
            return None

        # 2. Probe typed candidates
        for inferred_type, candidates in self._CANDIDATES:
            for candidate in candidates:
                status, size = self._fetch(f"{base_url}/{candidate}")
                if status is None:
                    continue
                if self._differs_from_baseline(status, size, baseline_status, baseline_size):
                    param_name = self._param_name_for(endpoint, inferred_type)
                    normalised = f"{endpoint.rstrip('/')}/{{{param_name}}}"
                    return {
                        'normalised_path': normalised,
                        'original_endpoint': endpoint,
                        'methods': methods,
                        'param_name': param_name,
                        'param_type': inferred_type,
                        'param_format': 'uuid' if inferred_type == 'uuid' else None,
                        'example_value': candidate,
                        'hit_status': status,
                    }
        return None

    def _differs_from_baseline(self, status: int, size: int,
                                b_status: int, b_size: int) -> bool:
        """
        A response is a "hit" when it differs from baseline by status code
        OR by more than _SIZE_DELTA_THRESHOLD bytes (catches 200→200 where
        the body changes from an error message to actual data).
        """
        if status != b_status:
            return True
        if abs(size - b_size) > self._SIZE_DELTA_THRESHOLD:
            return True
        return False

    @staticmethod
    def _param_name_for(endpoint: str, inferred_type: str) -> str:
        """
        Derive a meaningful parameter name from the endpoint segment and type.

        ``api/users``  + integer → ``user_id``
        ``api/articles`` + slug   → ``article_slug``
        ``api/items``  + uuid   → ``item_uuid``
        """
        # Last non-empty segment of the endpoint
        segments = [s for s in endpoint.split('/') if s]
        resource = segments[-1] if segments else 'resource'

        # De-pluralise simple English plurals (users→user, articles→article)
        singular = re.sub(r'ies$', 'y', resource)
        singular = re.sub(r's$', '', singular) if not singular.endswith('ss') else singular

        suffix_map = {'integer': 'id', 'uuid': 'uuid', 'slug': 'slug'}
        return f"{singular}_{suffix_map.get(inferred_type, 'id')}"

    @staticmethod
    def openapi_schema_for(param_type: str, param_format: Optional[str]) -> Dict:
        """Return an OpenAPI-compatible schema dict for a path parameter."""
        schema: Dict = {}
        if param_type == 'integer':
            schema = {'type': 'integer', 'example': 1}
        elif param_type == 'uuid':
            schema = {'type': 'string', 'format': 'uuid',
                      'example': '550e8400-e29b-41d4-a716-446655440000'}
        else:
            schema = {'type': 'string', 'example': 'current'}
        if param_format and 'format' not in schema:
            schema['format'] = param_format
        return schema


class OpenAPISpecGenerator:
    """Generates OpenAPI specification from discovered endpoints and parameters"""
    
    def __init__(self, api_title: str = "Discovered API", api_version: str = "1.0.0",
                 base_url: str = "http://127.0.0.1:5000"):
        self.api_title = api_title
        self.api_version = api_version
        self.base_url = base_url
        self.paths = {}
        self.parameter_extractor = ParameterExtractor()
    
    def add_endpoint(self, endpoint: str, methods: Set[str], 
                     parameters: Dict[str, Dict] = None):
        """
        Add an endpoint to the OpenAPI spec
        
        Args:
            endpoint: The endpoint path (e.g., "users" or "users/{id}")
            methods: Set of HTTP methods (GET, POST, etc.)
            parameters: Optional dict of parameters by method
        """
        # Skip file-based resources
        file_extensions = [
            '.js', '.css', '.json', '.map', '.woff', '.woff2', '.ttf', '.eot',
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.tar', '.gz',
            '.mp3', '.mp4', '.mov', '.avi', '.flv', '.wmv', '.wav',
            '.txt', '.csv', '.xml', '.html', '.htm'
        ]
        
        for ext in file_extensions:
            if endpoint.endswith(ext) or f"{ext}?" in endpoint:
                return  # Skip this endpoint
        
        path = f"/{endpoint}" if not endpoint.startswith('/') else endpoint
        
        if path not in self.paths:
            self.paths[path] = {}
        
        for method in methods:
            method_lower = method.lower()
            
            # Extract path parameters
            path_params = ParameterExtractor.extract_path_params_from_pattern(endpoint)
            
            operation = {
                "summary": f"{method} /{endpoint}",
                "operationId": f"{method_lower}_{endpoint.replace('/', '_').replace('-', '_')}",
                "tags": [endpoint.split('/')[0] if '/' in endpoint else endpoint],
                "parameters": []
            }
            
            # Add path parameters
            for param_name, param_type in path_params.items():
                operation["parameters"].append({
                    "name": param_name,
                    "in": "path",
                    "required": True,
                    "schema": {"type": param_type}
                })
            
            # Add query parameters (for GET methods)
            if method.upper() == 'GET' and parameters:
                method_params = parameters.get(method.upper(), {})
                query_params = method_params.get('query', {})
                for param_name, param_info in query_params.items():
                    operation["parameters"].append({
                        "name": param_name,
                        "in": "query",
                        "required": False,
                        "schema": {"type": param_info.get("type", "string")},
                        "example": param_info.get("example", "")
                    })
            
            # Add request body (for POST/PUT/PATCH methods)
            if method.upper() in ['POST', 'PUT', 'PATCH', 'DELETE']:
                body_params = {}
                form_params = {}
                if parameters:
                    method_params = parameters.get(method.upper(), {})
                    body_params = method_params.get('body', {})
                    form_params = method_params.get('formData', {})
                
                if body_params or form_params:
                    content_type = "application/x-www-form-urlencoded" if form_params else "application/json"
                    
                    properties = {}
                    if form_params:
                        properties = {k: {"type": v.get("type", "string")} 
                                    for k, v in form_params.items()}
                    else:
                        properties = {k: {"type": v.get("type", "string")} 
                                    for k, v in body_params.items()}
                    
                    operation["requestBody"] = {
                        "content": {
                            content_type: {
                                "schema": {
                                    "type": "object",
                                    "properties": properties
                                }
                            }
                        }
                    }
            
            # Add response
            operation["responses"] = {
                "200": {
                    "description": "Successful response",
                    "content": {
                        "application/json": {
                            "schema": {"type": "object"}
                        }
                    }
                },
                "400": {"description": "Bad request"},
                "401": {"description": "Unauthorized"},
                "403": {"description": "Forbidden"},
                "404": {"description": "Not found"}
            }
            
            self.paths[path][method_lower] = operation
    
    def generate_spec(self) -> Dict:
        """Generate complete OpenAPI 3.0.0 specification"""
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": self.api_title,
                "version": self.api_version,
                "description": "API specification auto-generated from endpoint discovery"
            },
            "servers": [{"url": self.base_url}],
            "paths": self.paths
        }
        return spec
    
    def save_spec(self, output_file: str):
        """Save OpenAPI spec to JSON file"""
        spec = self.generate_spec()
        with open(output_file, 'w') as f:
            json.dump(spec, f, indent=2)
        print(f"OpenAPI specification saved to {output_file}")
    
    def save_spec_yaml(self, output_file: str):
        """Save OpenAPI spec to YAML file"""
        try:
            import yaml
            spec = self.generate_spec()
            with open(output_file, 'w') as f:
                yaml.dump(spec, f, default_flow_style=False)
            print(f"OpenAPI specification (YAML) saved to {output_file}")
        except ImportError:
            print("WARNING: PyYAML not installed. Install with: pip3 install pyyaml")
            print(f"Saving as JSON instead: {output_file.replace('.yaml', '.json')}")
            self.save_spec(output_file.replace('.yaml', '.json'))


class ParameterizedEndpointFuzzer:
    """Discovers parameterized endpoints like /resource/{id} by fuzzing discovered endpoints"""
    
    def __init__(self, target_url: str, output_dir: str = "./fuzzing_results",
                 follow_redirects: bool = True, match_codes: str = "200,201,401,403"):
        self.target_url = target_url.rstrip('/')
        self.output_dir = output_dir
        self.follow_redirects = follow_redirects
        self.match_codes = match_codes
        self.response_parser = ResponseParser()
        
        # Common parameter patterns to test
        self.param_patterns = [
            '{id}', '{ID}', '/{id}',
            '{uuid}', '/{uuid}',
            '{pk}', '/{pk}',
            '/{resource_id}', '{resource_id}',
            '/{itemId}', '{itemId}',
            '/{item_id}', '{item_id}',
            '/1', '/123', '/test',  # Common test values
            '/{identifier}', '{identifier}'
        ]
        
        self.discovered_params = {}  # endpoint -> list of working parameter patterns
    
    @staticmethod
    def extract_id_candidates_from_response(content: str) -> Set[str]:
        """
        Extract potential ID values from response content
        
        Returns:
            Set of potential ID values to use for parameterized endpoints
        """
        candidates = set()
        
        # Pattern 1: Extract numbers that look like IDs
        id_pattern = r'"(?:id|ID|pk|uuid|itemId|resource_id|identifier)"?\s*:\s*["\']?(\d+)["\']?'
        matches = re.findall(id_pattern, content)
        candidates.update(matches[:5])  # Limit to first 5
        
        # Pattern 2: Extract UUID patterns
        uuid_pattern = r'([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})'
        matches = re.findall(uuid_pattern, content, re.IGNORECASE)
        candidates.update(matches[:3])  # Limit to first 3
        
        # Pattern 3: Extract hash-like IDs
        hash_pattern = r'["\']([a-f0-9]{20,})["\']'
        matches = re.findall(hash_pattern, content, re.IGNORECASE)
        candidates.update(matches[:3])
        
        return candidates
    
    def fuzz_endpoint_with_parameters(self, endpoint: str, method: str = 'GET',
                                      timeout: int = 10, test_values: List[str] = None) -> Dict[str, Dict]:
        """
        Try common parameter patterns on an endpoint
        
        Args:
            endpoint: Base endpoint (e.g., "career")
            method: HTTP method to test
            timeout: Request timeout
            test_values: List of test values to use (default: [1, 123, test])
        
        Returns:
            Dict of successful patterns and their responses
        """
        if test_values is None:
            test_values = ['1', '123', 'test']
        
        successful_patterns = {}
        
        # Test endpoint with different parameter patterns
        for pattern in self.param_patterns:
            # Replace parameter placeholder with test value
            parameterized_endpoint = pattern
            if '{' in pattern:
                # Extract parameter name and create variations
                param_name = re.search(r'\{([^}]+)\}', pattern).group(1)
                
                for test_val in test_values:
                    test_endpoint = pattern.replace(f'{{{param_name}}}', test_val)
                    url = f"{self.target_url}/{endpoint}{test_endpoint}"
                    
                    try:
                        status, content = self.response_parser.fetch_endpoint(url, method, timeout)
                        
                        # Consider 200-299 as successful
                        if status and 200 <= status < 300:
                            if pattern not in successful_patterns:
                                successful_patterns[pattern] = {
                                    'test_value': test_val,
                                    'status': status,
                                    'param_name': param_name
                                }
                            return successful_patterns  # Found one, return early
                    except:
                        pass
        
        return successful_patterns
    
    def discover_parameterized_endpoints(self, endpoints: Dict[str, Set[str]],
                                        timeout: int = 10) -> Dict[str, Dict]:
        """
        Intelligently fuzz discovered endpoints to find parameterized variants
        
        Args:
            endpoints: Dictionary of discovered endpoints with methods
            timeout: Request timeout
        
        Returns:
            Dictionary of discovered parameterized endpoints
        """
        parameterized = {}
        
        print(f"\n{'='*80}")
        print("DISCOVERING PARAMETERIZED ENDPOINTS")
        print(f"{'='*80}")
        print(f"Testing {len(endpoints)} endpoints for parameter patterns...\n")
        
        for endpoint in sorted(endpoints.keys()):
            methods = endpoints[endpoint]
            
            # Skip endpoints that already have parameters
            if any(c in endpoint for c in ['{', '}', ':', '[']):
                continue
            
            # Skip root and very short endpoints
            if endpoint in ['', '/'] or len(endpoint) < 2:
                continue
            
            print(f"Testing {endpoint}...", end=" ", flush=True)
            
            # Test with GET first (most common)
            found = False
            for method in list(methods) + ['GET', 'POST']:
                # First, fetch the base endpoint to extract test values
                try:
                    base_url = f"{self.target_url}/{endpoint}"
                    status, content = self.response_parser.fetch_endpoint(base_url, method, timeout)
                    
                    if status and content and 200 <= status < 300:
                        # Extract potential ID values from response
                        test_values = list(self.extract_id_candidates_from_response(content))
                        
                        # If we found IDs in response, use them
                        if not test_values:
                            test_values = ['1', '123', 'test']
                        
                        # Fuzz with parameters
                        patterns = self.fuzz_endpoint_with_parameters(
                            endpoint, method, timeout, test_values
                        )
                        
                        if patterns:
                            parameterized[endpoint] = patterns
                            print(f"✓ Found patterns: {', '.join(patterns.keys())}")
                            found = True
                            break
                except:
                    pass
            
            if not found:
                print("✗")
        
        return parameterized


class SmartChainFuzzer:
    """Intelligent fuzzing that discovers endpoints from response analysis"""
    
    def __init__(self, target_url: str, wordlist: str, output_dir: str = "./smart_fuzzing",
                 follow_redirects: bool = True, match_codes: str = "200,201,401,403",
                 katana_crawler: Optional['KatanaCrawler'] = None):
        self.target_url = target_url.rstrip('/')
        self.wordlist = wordlist
        self.output_dir = output_dir
        self.follow_redirects = follow_redirects
        self.match_codes = match_codes
        self.discovered_endpoints = {}
        self.visited_endpoints = set()
        self.endpoint_parameters = {}
        self.response_parser = ResponseParser()
        self.fuzzer = APIFuzzer(target_url, wordlist, output_dir, follow_redirects, match_codes)
        self.katana = katana_crawler   # None = ffuf-only mode
        
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def smart_discovery(self, methods: List[str] = None, threads: int = 40, 
                       timeout: int = 10, max_iterations: int = 3,
                       discover_params: bool = False) -> Dict:
        """
        Intelligent discovery workflow:
        1. Fuzz root with wordlist
        2. Fetch each discovered endpoint
        3. Extract endpoint references from responses
        4. Add new endpoints to fuzzing queue
        5. Repeat until no new endpoints found or max iterations reached
        6. Optionally discover parameterized endpoints like /resource/{id}
        
        Args:
            methods: HTTP methods to test
            threads: Fuzzing threads
            timeout: Request timeout
            max_iterations: Maximum discovery iterations
            discover_params: Whether to discover parameterized endpoints
        
        Returns:
            Dictionary with all discovered endpoints
        """
        if methods is None:
            methods = ['GET', 'POST']

        print(f"\n{'='*80}")
        print("STARTING HYBRID SMART CHAIN DISCOVERY")
        print(f"{'='*80}")
        print(f"Target   : {self.target_url}")
        print(f"Katana   : {'enabled (' + ('headless' if self.katana and self.katana.headless else 'standard') + ')' if self.katana else 'disabled (ffuf-only)'}")
        print(f"ffuf     : enabled (wordlist bruteforce)")
        print(f"Methods  : {methods}")
        print(f"Max iter : {max_iterations}")

        # ------------------------------------------------------------------ #
        #  PHASE A — Katana crawl (if available)                             #
        # ------------------------------------------------------------------ #
        if self.katana is not None:
            print(f"\n{'─'*80}")
            print("PHASE A: KATANA CRAWL")
            print(f"{'─'*80}")
            katana_results = self.katana.crawl()
            if katana_results:
                print(f"  Katana seeding {len(katana_results)} paths into discovery queue")
                for path, path_methods in katana_results.items():
                    self.discovered_endpoints[path] = path_methods

                # Absorb form field data as known parameters
                for path, methods_fields in self.katana.get_form_params().items():
                    self.endpoint_parameters.setdefault(path, {})
                    for method, fields in methods_fields.items():
                        self.endpoint_parameters[path][method] = {
                            'query':    {},
                            'body':     {k: {'type': 'string'} for k in fields},
                            'path':     {},
                            'formData': {k: {'type': 'string'} for k in fields},
                        }

                # Absorb XHR body keys as body parameters
                for path, raw_body in self.katana.get_xhr_bodies().items():
                    try:
                        body_dict = json.loads(raw_body)
                        if isinstance(body_dict, dict):
                            self.endpoint_parameters.setdefault(path, {})
                            for m in self.discovered_endpoints.get(path, {'POST'}):
                                ep = self.endpoint_parameters[path].setdefault(m, {
                                    'query': {}, 'body': {}, 'path': {}, 'formData': {}
                                })
                                ep['body'].update({k: {'type': 'string'} for k in body_dict})
                    except (json.JSONDecodeError, TypeError):
                        pass
            else:
                print("  Katana returned no results")

        # ------------------------------------------------------------------ #
        #  PHASE B — Root HTML + JS mining                                   #
        # ------------------------------------------------------------------ #
        print(f"\n{'─'*80}")
        print("PHASE B: Root HTML / JS mining")
        print(f"{'─'*80}")
        _root_candidates = ['', 'index.html', 'index.php', 'index.htm', 'app', 'home']
        _root_js_endpoints: Set[str] = set()

        def _fetch_root(rc: str):
            url = f"{self.target_url}/{rc}".rstrip('/')
            status, content = self.response_parser.fetch_endpoint(url, 'GET', timeout, retries=2)
            return rc, url, status, content

        with ThreadPoolExecutor(max_workers=len(_root_candidates)) as pool:
            futures = [pool.submit(_fetch_root, rc) for rc in _root_candidates]
            for future in as_completed(futures):
                rc, url, status, content = future.result()
                if status and content:
                    print(f"  ✓ Fetched /{rc or '(root)'}  [{status}]")
                    js_found = self.response_parser.discover_endpoints_from_js_files(
                        content, url, timeout, max_workers=10
                    )
                    if js_found:
                        print(f"    ↳ JS mining: {len(js_found)} candidate(s)")
                        _root_js_endpoints.update(js_found)
                    _root_js_endpoints.update(
                        self.response_parser.extract_endpoints_from_response(content, url)
                    )

        _valid_count = 0
        _candidates_b = [ep for ep in _root_js_endpoints if ep not in self.discovered_endpoints]
        if _candidates_b:
            print(f"  Validating {len(_candidates_b)} candidate(s) "
                  f"({min(threads, 30)} workers)…")

            def _validate_root_ep(ep: str):
                probe_url = f"{self.target_url}/{ep.lstrip('/')}"
                s, _ = self.response_parser.fetch_endpoint(probe_url, 'GET', timeout, retries=1)
                return ep, s

            with ThreadPoolExecutor(max_workers=min(threads, 30)) as pool:
                futures = [pool.submit(_validate_root_ep, ep) for ep in _candidates_b]
                for future in as_completed(futures):
                    ep, s = future.result()
                    if s and s not in (404, 405, 410):
                        self.discovered_endpoints[ep] = {'GET'}
                        _valid_count += 1
        print(f"  {_valid_count}/{len(_root_js_endpoints)} validated and pre-seeded")

        # ------------------------------------------------------------------ #
        #  PHASE C — ffuf wordlist fuzzing                                   #
        #  Finds endpoints never linked anywhere — only reachable by         #
        #  brute-forcing from a wordlist.  Skipped if no wordlist provided.  #
        # ------------------------------------------------------------------ #
        print(f"\n{'─'*80}")
        print("PHASE C: ffuf wordlist bruteforce")
        print(f"{'─'*80}")

        if not self.wordlist or not os.path.exists(self.wordlist):
            print(f"  Wordlist not found ({self.wordlist}) — skipping ffuf phase")
            print(f"  (Running Katana-only mode — use -w to add wordlist fuzzing)")
        else:
            print(f"  Wordlist : {self.wordlist}   Methods: {methods}")
            try:
                method_results = self.fuzzer.fuzz_with_methods(methods, threads, timeout)

                if not method_results and not self.fuzzer.check_ffuf_installed():
                    print("  ffuf not installed — skipping. Install: brew install ffuf")
                else:
                    for method, endpoints in method_results.items():
                        print(f"  {method}: {len(endpoints)} endpoints from ffuf")
                        for endpoint, eps_methods in endpoints.items():
                            if endpoint not in self.discovered_endpoints:
                                self.discovered_endpoints[endpoint] = set()
                            self.discovered_endpoints[endpoint].update(eps_methods)

            except Exception as e:
                print(f"  ffuf error: {e}")

        print(f"\n  Combined (Katana + JS mining + ffuf): "
              f"{len(self.discovered_endpoints)} unique endpoints before iteration")

        # ------------------------------------------------------------------ #
        #  PHASE D — Iterative response analysis                             #
        # ------------------------------------------------------------------ #
        # Iterative response analysis
        iteration = 2
        while iteration <= max_iterations:
            print(f"\n{'─'*80}")
            print(f"PHASE D — ITERATION {iteration}: Response analysis and JS discovery")
            print(f"{'─'*80}")
            
            new_endpoints = set()
            retry_queue: Set[str] = set()
            endpoints_to_check = set(self.discovered_endpoints.keys()) - self.visited_endpoints
            
            if not endpoints_to_check:
                print("No new endpoints to analyze")
                break
            
            print(f"Checking {len(endpoints_to_check)} endpoints for references "
                  f"({threads} concurrent workers)...")

            # Build the work list: (endpoint, method) pairs.
            # Only test methods we actually know respond for this endpoint
            # (from ffuf/Katana) instead of blindly trying GET+POST on
            # everything — this alone roughly halves the request count for
            # endpoints that are GET-only or POST-only.
            work_items: List[Tuple[str, str]] = []
            for endpoint in sorted(endpoints_to_check):
                self.visited_endpoints.add(endpoint)
                known_methods = self.discovered_endpoints.get(endpoint) or {'GET'}
                # Always include GET — JS/HTML mining only makes sense on GET
                for method in (known_methods | {'GET'}):
                    work_items.append((endpoint, method))

            def _fetch_and_mine(item: Tuple[str, str]):
                endpoint, method = item
                url = f"{self.target_url}/{endpoint}"
                # retries=1 here: a real retry pass with timeout×2 happens
                # below for anything that comes back None, so we fail fast
                # on the first attempt to keep the pool moving.
                status, content = self.response_parser.fetch_endpoint(
                    url, method, timeout, retries=1
                )
                return endpoint, method, url, status, content

            completed = 0
            with ThreadPoolExecutor(max_workers=min(threads, 100)) as pool:
                futures = {pool.submit(_fetch_and_mine, item): item for item in work_items}
                for future in as_completed(futures):
                    endpoint, method = futures[future]
                    completed += 1
                    try:
                        _, _, url, status, content = future.result()
                    except Exception as e:
                        if completed % 25 == 0 or completed == len(work_items):
                            print(f"  [{completed}/{len(work_items)}] processed…")
                        continue

                    if status and content and status in [200, 201, 401, 403]:
                        extracted = self.response_parser.extract_endpoints_from_response(
                            content, url
                        )
                        if extracted:
                            new_endpoints.update(extracted)

                        js_endpoints = self.response_parser.discover_endpoints_from_js_files(
                            content, url, timeout, max_workers=5
                        )
                        if js_endpoints:
                            new_endpoints.update(js_endpoints)

                        params = self.response_parser.analyze_response_for_parameters(
                            content, url, method
                        )
                        self.endpoint_parameters.setdefault(endpoint, {})[method] = params
                    elif status is None:
                        retry_queue.add(endpoint)

                    if completed % 25 == 0 or completed == len(work_items):
                        print(f"  [{completed}/{len(work_items)}] processed "
                              f"({len(new_endpoints)} new candidates so far)…")
            
            # Re-try endpoints that timed out, with a longer timeout — concurrently
            if retry_queue:
                print(f"\n  Retrying {len(retry_queue)} timed-out endpoints "
                      f"(timeout×2, {min(threads, 30)} workers)…")

                def _retry_one(endpoint: str):
                    url = f"{self.target_url}/{endpoint}"
                    self.visited_endpoints.discard(endpoint)
                    status, content = self.response_parser.fetch_endpoint(
                        url, 'GET', timeout * 2, retries=1
                    )
                    return endpoint, url, status, content

                with ThreadPoolExecutor(max_workers=min(threads, 30)) as pool:
                    futures = [pool.submit(_retry_one, ep) for ep in sorted(retry_queue)]
                    for future in as_completed(futures):
                        endpoint, url, status, content = future.result()
                        if status and content and status in [200, 201, 401, 403]:
                            print(f"  ✓ Retry succeeded for /{endpoint} [{status}]")
                            extracted = self.response_parser.extract_endpoints_from_response(content, url)
                            new_endpoints.update(extracted)
                            js_ep = self.response_parser.discover_endpoints_from_js_files(content, url, timeout * 2)
                            new_endpoints.update(js_ep)
                        else:
                            print(f"  ✗ Retry failed for /{endpoint}")

            # Validate and add new endpoints — probe each one before committing
            # it to discovered_endpoints so that CSS classes, locale strings, and
            # other false positives that return 404 are silently discarded.
            # Probes run concurrently since each is an independent request.
            newly_added = 0
            candidates = [ep for ep in new_endpoints if ep not in self.discovered_endpoints]
            if candidates:
                print(f"\n  Validating {len(candidates)} candidate endpoint(s) "
                      f"({min(threads, 50)} workers)…")

                def _validate_one(endpoint: str):
                    _url = f"{self.target_url}/{endpoint.lstrip('/')}"
                    _s, _ = self.response_parser.fetch_endpoint(_url, 'GET', timeout, retries=1)
                    return endpoint, _s

                with ThreadPoolExecutor(max_workers=min(threads, 50)) as pool:
                    futures = [pool.submit(_validate_one, ep) for ep in candidates]
                    for future in as_completed(futures):
                        endpoint, status = future.result()
                        if status and status not in (404, 405, 410):
                            self.discovered_endpoints[endpoint] = {'GET', 'POST'}
                            newly_added += 1
            
            print(f"\nIteration {iteration}: Found {newly_added} new endpoints")
            print(f"Total unique endpoints so far: {len(self.discovered_endpoints)}")
            
            if newly_added == 0:
                print("No new endpoints found - stopping discovery")
                break
            
            iteration += 1
        
        # Path-parameter discovery (always runs, not gated on discover_params flag)
        print(f"\n{'─'*80}")
        print("PATH PARAMETER DISCOVERY")
        print(f"{'─'*80}")
        prober = PathParamProber(
            self.target_url, timeout=timeout, retries=2,
            max_workers=10
        )
        path_param_hits = prober.probe_all(self.discovered_endpoints)

        if path_param_hits:
            for norm_path, meta in path_param_hits.items():
                if norm_path not in self.discovered_endpoints:
                    self.discovered_endpoints[norm_path] = meta['methods']
                # Store the inferred parameter schema for OpenAPI export
                param_schema = PathParamProber.openapi_schema_for(
                    meta['param_type'], meta['param_format']
                )
                if meta['original_endpoint'] not in self.endpoint_parameters:
                    self.endpoint_parameters[meta['original_endpoint']] = {}
                for m in meta['methods']:
                    ep_params = self.endpoint_parameters[meta['original_endpoint']].setdefault(m, {})
                    ep_params.setdefault('path', {})[meta['param_name']] = param_schema

            print(f"Total endpoints after path-param discovery: {len(self.discovered_endpoints)}")
        else:
            print("No path-parameter variants found.")
        
        self._save_discovery_results()
        
        return {
            'total_endpoints': len(self.discovered_endpoints),
            'endpoints': self.discovered_endpoints,
            'iterations': iteration - 1
        }
    
    def _save_discovery_results(self):
        """Save discovery results to file"""
        results_file = os.path.join(self.output_dir, 'smart_discovery_results.txt')
        json_file = os.path.join(self.output_dir, 'smart_discovery_results.json')
        
        # Save text format
        with open(results_file, 'w') as f:
            f.write("SMART CHAIN DISCOVERY RESULTS\n")
            f.write(f"{'='*80}\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Total endpoints discovered: {len(self.discovered_endpoints)}\n\n")
            
            f.write(f"{'Endpoint':<50} {'Methods'}\n")
            f.write(f"{'-'*80}\n")
            
            for endpoint in sorted(self.discovered_endpoints.keys()):
                methods = ', '.join(sorted(self.discovered_endpoints[endpoint]))
                f.write(f"{endpoint:<50} {methods}\n")
        
        # Save JSON format
        with open(json_file, 'w') as f:
            json.dump({
                'endpoints': {
                    ep: list(methods)
                    for ep, methods in sorted(self.discovered_endpoints.items())
                },
                'total': len(self.discovered_endpoints)
            }, f, indent=2)
        
        print(f"\nDiscovery results saved to:")
        print(f"  - {results_file}")
        print(f"  - {json_file}")


class APIAnalyzer:
    """Analyzes and combines endpoint data"""
    
    def __init__(self):
        self.all_endpoints = {}
        self.endpoint_sources = defaultdict(set)  # Track which sources found each endpoint
        self.endpoint_parameters = {}  # Track parameters for each endpoint-method
        self.parameter_extractor = ParameterExtractor()

    
    def add_endpoints(self, endpoints: Dict[str, Set[str]], source: str):
        """
        Add endpoints from a source
        
        Args:
            endpoints: Dictionary of endpoints with methods
            source: Source name (e.g., 'ffuf', 'ajax', 'html')
        """
        for endpoint, methods in endpoints.items():
            if endpoint not in self.all_endpoints:
                self.all_endpoints[endpoint] = set()
            
            self.all_endpoints[endpoint].update(methods)
            self.endpoint_sources[endpoint].add(source)
    
    def merge_endpoints_dicts(self, *dicts: Dict[str, Set[str]]):
        """Merge multiple endpoint dictionaries"""
        for endpoint_dict in dicts:
            for endpoint, methods in endpoint_dict.items():
                if endpoint not in self.all_endpoints:
                    self.all_endpoints[endpoint] = set()
                self.all_endpoints[endpoint].update(methods)
    
    def get_statistics(self) -> Dict:
        """Get statistics about discovered endpoints"""
        total_endpoints = len(self.all_endpoints)
        total_methods = sum(len(methods) for methods in self.all_endpoints.values())
        
        method_counts = defaultdict(int)
        for methods in self.all_endpoints.values():
            for method in methods:
                method_counts[method] += 1
        
        return {
            'total_endpoints': total_endpoints,
            'total_methods': total_methods,
            'method_counts': dict(method_counts),
        }
    
    def print_results(self):
        """Print formatted results"""
        print(f"\n{'='*70}")
        print("ENDPOINT DISCOVERY RESULTS")
        print(f"{'='*70}\n")
        
        stats = self.get_statistics()
        print(f"Total unique endpoints: {stats['total_endpoints']}")
        print(f"Total methods: {stats['total_methods']}")
        print(f"Method breakdown: {stats['method_counts']}\n")
        
        print(f"{'Endpoint':<50} {'Methods':<20} {'Sources'}")
        print("-" * 100)
        
        for endpoint in sorted(self.all_endpoints.keys()):
            methods = ', '.join(sorted(self.all_endpoints[endpoint]))
            sources = ', '.join(sorted(self.endpoint_sources[endpoint]))
            print(f"{endpoint:<50} {methods:<20} {sources}")
    
    def save_to_file(self, output_file: str):
        """Save results to file"""
        with open(output_file, 'w') as f:
            f.write("ENDPOINT DISCOVERY RESULTS\n")
            f.write("=" * 70 + "\n\n")
            
            stats = self.get_statistics()
            f.write(f"Total unique endpoints: {stats['total_endpoints']}\n")
            f.write(f"Total methods: {stats['total_methods']}\n")
            f.write(f"Method breakdown: {stats['method_counts']}\n\n")
            
            f.write(f"{'Endpoint':<50} {'Methods':<20} {'Sources'}\n")
            f.write("-" * 100 + "\n")
            
            for endpoint in sorted(self.all_endpoints.keys()):
                methods = ', '.join(sorted(self.all_endpoints[endpoint]))
                sources = ', '.join(sorted(self.endpoint_sources[endpoint]))
                f.write(f"{endpoint:<50} {methods:<20} {sources}\n")
    
    def export_json(self, output_file: str):
        """Export results to JSON"""
        data = {
            'endpoints': {
                endpoint: list(methods) 
                for endpoint, methods in sorted(self.all_endpoints.items())
            },
            'statistics': self.get_statistics(),
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def add_endpoint_parameters(self, endpoint: str, method: str, params: Dict):
        """
        Track parameters for an endpoint-method combination
        
        Args:
            endpoint: The endpoint path
            method: HTTP method (GET, POST, etc.)
            params: Dictionary of parameters (can have 'query', 'path', 'body', 'formData')
        """
        if endpoint not in self.endpoint_parameters:
            self.endpoint_parameters[endpoint] = {}
        
        if method not in self.endpoint_parameters[endpoint]:
            self.endpoint_parameters[endpoint][method] = {
                'query': {},
                'path': {},
                'body': {},
                'formData': {}
            }
        
        # Merge parameters
        for param_type, param_data in params.items():
            if param_type in self.endpoint_parameters[endpoint][method]:
                self.endpoint_parameters[endpoint][method][param_type].update(param_data)
    
    def generate_openapi_spec(self, api_title: str = "Discovered API", 
                            api_version: str = "1.0.0",
                            base_url: str = "http://127.0.0.1:5000") -> Dict:
        """
        Generate OpenAPI 3.0.0 specification from discovered endpoints
        
        Args:
            api_title: Title for the API
            api_version: Version of the API
            base_url: Base URL for the API
        
        Returns:
            OpenAPI specification dictionary
        """
        spec_generator = OpenAPISpecGenerator(api_title, api_version, base_url)
        
        for endpoint, methods in self.all_endpoints.items():
            params = self.endpoint_parameters.get(endpoint, {})
            spec_generator.add_endpoint(endpoint, methods, params)
        
        return spec_generator.generate_spec()
    
    def export_openapi_spec(self, output_file: str, api_title: str = "Discovered API",
                           api_version: str = "1.0.0", 
                           base_url: str = "http://127.0.0.1:5000"):
        """
        Export results as OpenAPI specification
        
        Args:
            output_file: Output file path (.json or .yaml)
            api_title: Title for the API
            api_version: Version of the API
            base_url: Base URL for the API
        """
        spec_generator = OpenAPISpecGenerator(api_title, api_version, base_url)
        
        for endpoint, methods in self.all_endpoints.items():
            params = self.endpoint_parameters.get(endpoint, {})
            spec_generator.add_endpoint(endpoint, methods, params)
        
        if output_file.endswith('.yaml') or output_file.endswith('.yml'):
            spec_generator.save_spec_yaml(output_file)
        else:
            spec_generator.save_spec(output_file)
        
        print(f"OpenAPI specification exported to {output_file}")



class APIDiscoveryTool:
    """Main tool orchestrating all discovery operations"""
    
    def __init__(self, target_url: str = None, wordlist: str = None, 
                 output_dir: str = "./fuzzing_results", follow_redirects: bool = True,
                 match_codes: str = "200,201,401,403"):
        self.target_url = target_url
        self.wordlist = wordlist
        self.output_dir = output_dir
        self.follow_redirects = follow_redirects
        self.match_codes = match_codes
        self.analyzer = APIAnalyzer()
        self.extractor = EndpointExtractor()
        self.fuzzer = None
        
        if target_url and wordlist:
            self.fuzzer = APIFuzzer(
                target_url, 
                wordlist, 
                output_dir=output_dir,
                follow_redirects=follow_redirects,
                match_codes=match_codes
            )
    
    def run_fuzzing(self, threads: int = 40, timeout: int = 10, output_filename: str = "ffuf_results.json"):
        """Run fuzzing against target API"""
        if not self.fuzzer:
            print("Error: No fuzzer configured")
            return False
        
        success = self.fuzzer.fuzz_with_ffuf(threads, timeout, output_filename=output_filename)
        if success:
            endpoints = self.fuzzer.extract_endpoints_from_ffuf_results()
            self.analyzer.add_endpoints(endpoints, 'ffuf')
        
        return success
    
    def analyze_ffuf_directories(self, *directories):
        """Analyze ffuf results from directories"""
        for directory in directories:
            if not os.path.exists(directory):
                print(f"Directory {directory} not found")
                continue
            
            print(f"\n{'='*70}")
            print(f"Analyzing: {directory}")
            print(f"{'='*70}")
            
            endpoints_from_dir = {}
            
            for filename in os.listdir(directory):
                filepath = os.path.join(directory, filename)
                
                if not os.path.isfile(filepath):
                    continue
                
                try:
                    content = self.extractor.open_file(filepath)
                    endpoint, method = self.extractor.extract_from_http_request(content)
                    
                    if endpoint and method:
                        if endpoint not in endpoints_from_dir:
                            endpoints_from_dir[endpoint] = set()
                        endpoints_from_dir[endpoint].add(method)
                
                except Exception as e:
                    print(f"Error processing {filepath}: {e}")
            
            print(f"Found {len(endpoints_from_dir)} endpoints")
            self.analyzer.add_endpoints(endpoints_from_dir, os.path.basename(directory))
    
    def analyze_html_files(self, html_directory: str = None):
        """Analyze HTML files for AJAX endpoints"""
        search_dir = html_directory or '.'
        
        if not os.path.exists(search_dir):
            print(f"Directory {search_dir} not found")
            return
        
        print(f"\n{'='*70}")
        print("Analyzing HTML files for AJAX endpoints")
        print(f"{'='*70}")
        
        html_files = [f for f in os.listdir(search_dir) if f.endswith('.html')]
        
        if not html_files:
            print(f"No HTML files found in {search_dir}")
            return
        
        ajax_endpoints = {}
        
        for html_file in html_files:
            filepath = os.path.join(search_dir, html_file)
            print(f"Processing {html_file}...")
            
            content = self.extractor.open_file(filepath)
            endpoints = self.extractor.extract_ajax_endpoints(content)
            
            for endpoint, methods in endpoints.items():
                if endpoint not in ajax_endpoints:
                    ajax_endpoints[endpoint] = set()
                ajax_endpoints[endpoint].update(methods)
        
        print(f"Found {len(ajax_endpoints)} endpoints from AJAX calls")
        self.analyzer.add_endpoints(ajax_endpoints, 'ajax')
    
    def print_summary(self):
        """Print summary of discovered APIs"""
        self.analyzer.print_results()
    
    def save_results(self, output_file: str, json_file: str = None):
        """Save results to files"""
        self.analyzer.save_to_file(output_file)
        print(f"\nResults saved to {output_file}")
        
        if json_file:
            self.analyzer.export_json(json_file)
            print(f"JSON export saved to {json_file}")


def main():
    parser = argparse.ArgumentParser(
        description='Unified API Discovery and Fuzzing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:

1. Simple fuzzing with GET and POST:
   python3 api_discovery.py -t http://127.0.0.1:5000 -w wordlist.txt -f --methods GET POST

2. Chained fuzzing with multiple wordlists (sequential + recursive):
   python3 api_discovery.py -t http://127.0.0.1:5000 --chain-wordlists common.txt api.txt admin.txt --recursive 2

3. Smart chain discovery (intelligent response analysis):
   python3 api_discovery.py -t http://127.0.0.1:5000 -w wordlist.txt --smart-chain --max-iterations 5

4. Smart chain with multiple methods:
   python3 api_discovery.py -t http://127.0.0.1:5000 -w wordlist.txt --smart-chain --methods GET POST PUT --max-iterations 4

5. Fuzz, discover params, generate OpenAPI:
   python3 api_discovery.py -t http://127.0.0.1:5000 -w wordlist.txt -f --param-wordlist params.txt --openapi spec.yaml

6. Fuzz, then analyze existing results, then analyze HTML:
   python3 api_discovery.py -t http://127.0.0.1:5000 -w wordlist.txt -f -d ./ffuf_matches -a . -o results.txt
        """
    )
    
    # Basic arguments
    parser.add_argument('-t', '--target', help='Target API URL (e.g., http://127.0.0.1:5000)')
    parser.add_argument('-w', '--wordlist', help='Wordlist file for fuzzing')
    parser.add_argument('-f', '--fuzz', action='store_true', help='Run fuzzing')
    
    # Fuzzing parameters
    parser.add_argument('--threads', type=int, default=40, help='Number of fuzzing threads (default: 40)')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds (default: 10)')
    parser.add_argument('--retry', type=int, default=2,
                       help='Retries for timed-out fetch requests (default: 2)')
    parser.add_argument('-mc', '--match-codes', default='200,201,401,403',
                       help='HTTP status codes to match (default: 200,201,401,403)')
    parser.add_argument('--methods', nargs='+', default=['GET', 'POST'],
                       help='HTTP methods to fuzz with (default: GET POST)')
    parser.add_argument('--no-follow-redirects', action='store_true',
                       help='Do not follow HTTP redirects')
    
    # Output options
    parser.add_argument('-od', '--output-dir', default='./fuzzing_results',
                       help='Output directory for results (default: ./fuzzing_results)')
    parser.add_argument('--output-file', default='ffuf_results.json',
                       help='Output filename for ffuf JSON (default: ffuf_results.json)')
    
    # Chained fuzzing workflow
    parser.add_argument('--chain-wordlists', nargs='+',
                       help='Chain multiple wordlists: use results from one as base for next')
    parser.add_argument('--recursive', type=int, default=1,
                       help='Recursion depth for discovered endpoints (default: 1)')
    
    # Smart chain discovery (response-based)
    parser.add_argument('--smart-chain', action='store_true',
                       help='Enable intelligent discovery from response analysis')
    parser.add_argument('--max-iterations', type=int, default=3,
                       help='Max iterations for smart chain discovery (default: 3)')
    parser.add_argument('--discover-params', action='store_true',
                       help='Discover parameterized endpoints like /resource/{id}')

    # Parameter fuzzing
    parser.add_argument('--param-wordlist',
                       help='Wordlist of parameter names; enables query/body param fuzzing on every discovered endpoint')
    parser.add_argument('--param-fuzz-workers', type=int, default=8,
                       help='Number of concurrent ffuf processes during parameter fuzzing (default: 8)')
    parser.add_argument('--js-workers', type=int, default=10,
                       help='Max concurrent workers for JS file fetching (default: 10)')
    parser.add_argument('--no-path-params', action='store_true',
                       help='Skip path-parameter probing (baseline-diff detection of /endpoint/{id})')

    # Katana integration
    parser.add_argument('--katana', action='store_true',
                       help='Enable Katana crawler alongside ffuf (requires katana in PATH)')
    parser.add_argument('--headless', action='store_true',
                       help='Run Katana in headless Chromium mode (executes JS, follows SPA routes)')
    parser.add_argument('--katana-depth', type=int, default=5,
                       help='Katana crawl depth (default: 5)')
    parser.add_argument('--katana-cookie', type=str, default=None,
                       help='Cookie header to pass to Katana for authenticated crawling '
                            '(e.g. "session=abc123")')
    parser.add_argument('--katana-only', action='store_true',
                       help='Use only Katana for discovery, skip ffuf entirely')
    
    # Analysis options
    parser.add_argument('-d', '--dirs', nargs='+', help='Analyze ffuf result directories')
    parser.add_argument('-a', '--analyze-html', nargs='?', const='.',
                       help='Analyze HTML files for AJAX endpoints')
    parser.add_argument('-o', '--output', default='api_discovery_results.txt',
                       help='Output file for final results (default: api_discovery_results.txt)')
    parser.add_argument('-j', '--json', help='JSON output file for final results')
    parser.add_argument('--openapi', help='OpenAPI specification output file (.json or .yaml)')
    parser.add_argument('--api-title', default='Discovered API', 
                       help='Title for the OpenAPI specification (default: Discovered API)')
    parser.add_argument('--api-version', default='1.0.0',
                       help='Version for the OpenAPI specification (default: 1.0.0)')
    
    args = parser.parse_args()

    follow_redirects = not args.no_follow_redirects

    # ------------------------------------------------------------------ #
    #  Shared helper: run parameter fuzzing against all known endpoints   #
    # ------------------------------------------------------------------ #
    def run_param_fuzzing(analyzer: 'APIAnalyzer', fuzzer: 'APIFuzzer'):
        """
        Fuzz every discovered endpoint for query/body parameter names.

        Each (endpoint, method) pair spawns its own ffuf subprocess. These are
        independent processes, so they run CONCURRENTLY via a thread pool
        instead of one-at-a-time — controlled by --param-fuzz-workers
        (default 8). ffuf's own --threads still controls per-process
        concurrency, so total connections ≈ param_fuzz_workers × threads;
        lower one or the other if the target can't keep up.
        """
        if not getattr(args, 'param_wordlist', None):
            return
        print(f"\n{'='*80}")
        print("PARAMETER FUZZING")
        print(f"{'='*80}")
        print(f"Wordlist: {args.param_wordlist}")

        work_items = [
            (endpoint, method)
            for endpoint, methods in analyzer.all_endpoints.items()
            for method in methods
        ]
        param_workers = min(getattr(args, 'param_fuzz_workers', 8), len(work_items) or 1)
        print(f"Endpoints×methods to fuzz: {len(work_items)}  "
              f"({param_workers} concurrent ffuf processes)")

        def _fuzz_one(item: Tuple[str, str]):
            endpoint, method = item
            found = fuzzer.fuzz_parameters(
                endpoint, args.param_wordlist, method=method,
                threads=args.threads, timeout=args.timeout,
            )
            return endpoint, method, found

        with ThreadPoolExecutor(max_workers=param_workers) as pool:
            futures = [pool.submit(_fuzz_one, item) for item in work_items]
            for future in as_completed(futures):
                endpoint, method, found = future.result()
                if found:
                    param_dict = {
                        'query': {p: {'type': 'string'} for p in found[endpoint]}
                        if method.upper() == 'GET'
                        else {},
                        'body': {p: {'type': 'string'} for p in found[endpoint]}
                        if method.upper() != 'GET'
                        else {},
                        'path': {},
                        'formData': {},
                    }
                    analyzer.add_endpoint_parameters(endpoint, method, param_dict)

    # ------------------------------------------------------------------ #
    #  Shared helper: export all outputs from an analyzer instance        #
    # ------------------------------------------------------------------ #
    def export_results(analyzer: 'APIAnalyzer', target_url: str):
        print(f"\nExporting results…")
        analyzer.save_to_file(args.output)
        print(f"  Text  → {args.output}")

        if args.json:
            analyzer.export_json(args.json)
            print(f"  JSON  → {args.json}")

        if args.openapi:
            analyzer.export_openapi_spec(
                args.openapi, args.api_title, args.api_version,
                target_url or "http://127.0.0.1:5000"
            )
            print(f"  OpenAPI → {args.openapi}")

    # ================================================================== #
    #  MODE 1 — Chained fuzzing                                           #
    # ================================================================== #
    if args.chain_wordlists:
        print("\n" + "="*80)
        print("CHAINED FUZZING WORKFLOW MODE")
        print("="*80)

        if not args.target:
            print("Error: --target required for chained fuzzing")
            sys.exit(1)

        workflow = ChainedFuzzingWorkflow(
            target_url=args.target,
            output_dir=args.output_dir,
            follow_redirects=follow_redirects,
            match_codes=args.match_codes
        )

        results = workflow.fuzz_wordlist_chain(
            wordlists=args.chain_wordlists,
            methods=args.methods,
            threads=args.threads,
            timeout=args.timeout,
            recursive_depth=args.recursive
        )

        print(f"\n{'='*80}")
        print(f"Chained fuzzing complete!")
        print(f"Total endpoints discovered: {results['total_endpoints']}")
        print(f"{'='*80}")

        # Build an analyzer so we can run param fuzzing + export
        analyzer = APIAnalyzer()
        analyzer.add_endpoints(results['endpoints'], 'chain')

        # Path-parameter probing
        if not getattr(args, 'no_path_params', False):
            print(f"\n{'─'*80}")
            print("PATH PARAMETER DISCOVERY")
            print(f"{'─'*80}")
            prober = PathParamProber(args.target, timeout=args.timeout,
                                     retries=args.retry, max_workers=args.js_workers)
            path_hits = prober.probe_all(analyzer.all_endpoints)
            for norm_path, meta in path_hits.items():
                analyzer.add_endpoints({norm_path: meta['methods']}, 'path_param')
                schema = PathParamProber.openapi_schema_for(meta['param_type'], meta['param_format'])
                for m in meta['methods']:
                    analyzer.add_endpoint_parameters(
                        meta['original_endpoint'], m,
                        {'path': {meta['param_name']: schema}, 'query': {}, 'body': {}, 'formData': {}}
                    )

        # Shared fuzzer for parameter discovery (use first wordlist)
        chain_fuzzer = APIFuzzer(
            args.target, args.chain_wordlists[0],
            output_dir=args.output_dir,
            follow_redirects=follow_redirects,
            match_codes=args.match_codes
        )
        run_param_fuzzing(analyzer, chain_fuzzer)

        analyzer.print_results()
        export_results(analyzer, args.target)
        return

    # ================================================================== #
    #  MODE 2 — Smart chain discovery (Katana + ffuf hybrid)             #
    # ================================================================== #
    if args.smart_chain:
        print("\n" + "="*80)
        print("HYBRID SMART CHAIN DISCOVERY MODE")
        print("="*80)

        if not args.target:
            print("Error: --target required")
            sys.exit(1)
        if not getattr(args, 'katana', False) and not getattr(args, 'katana_only', False) \
                and not getattr(args, 'headless', False) and not args.wordlist:
            print("Error: provide --wordlist and/or --katana / --headless")
            sys.exit(1)

        # Build Katana if requested
        _katana = None
        if getattr(args, 'katana', False) or getattr(args, 'headless', False) \
                or getattr(args, 'katana_only', False):
            _katana = KatanaCrawler(
                target_url=args.target,
                output_dir=args.output_dir,
                headless=getattr(args, 'headless', False),
                depth=getattr(args, 'katana_depth', 5),
                concurrency=args.threads,
                timeout=args.timeout,
                match_codes=args.match_codes,
                follow_redirects=follow_redirects,
                cookie=getattr(args, 'katana_cookie', None),
            )

        _wordlist = '' if getattr(args, 'katana_only', False) else (args.wordlist or '')

        smart_fuzzer = SmartChainFuzzer(
            target_url=args.target,
            wordlist=_wordlist,
            output_dir=args.output_dir,
            follow_redirects=follow_redirects,
            match_codes=args.match_codes,
            katana_crawler=_katana,
        )

        results = smart_fuzzer.smart_discovery(
            methods=args.methods,
            threads=args.threads,
            timeout=args.timeout,
            max_iterations=args.max_iterations,
            discover_params=args.discover_params
        )

        print(f"\n{'='*80}")
        print(f"Smart chain discovery complete!")
        print(f"Total endpoints discovered: {results['total_endpoints']}")
        print(f"Iterations completed: {results['iterations']}")
        print(f"{'='*80}")

        # Populate analyzer with discovered data
        analyzer = APIAnalyzer()
        analyzer.add_endpoints(results['endpoints'], 'smart_chain')

        for endpoint, methods_dict in smart_fuzzer.endpoint_parameters.items():
            for method, params in methods_dict.items():
                analyzer.add_endpoint_parameters(endpoint, method, params)

        # Optional parameter fuzzing pass
        run_param_fuzzing(analyzer, smart_fuzzer.fuzzer)

        analyzer.print_results()
        export_results(analyzer, args.target)
        return

    # ================================================================== #
    #  MODE 3 — Regular / directory / HTML analysis                      #
    # ================================================================== #
    tool = APIDiscoveryTool(
        target_url=args.target,
        wordlist=args.wordlist,
        output_dir=args.output_dir,
        follow_redirects=follow_redirects,
        match_codes=args.match_codes
    )

    if args.fuzz:
        if not args.target or not args.wordlist:
            print("Error: --target and --wordlist required for fuzzing")
            sys.exit(1)

        if tool.fuzzer and len(args.methods) > 1:
            print(f"\nFuzzing with multiple methods: {', '.join(args.methods)}")
            method_results = tool.fuzzer.fuzz_with_methods(args.methods, args.threads, args.timeout)
            for method, endpoints in method_results.items():
                tool.analyzer.add_endpoints(endpoints, f'ffuf_{method}')
        else:
            tool.run_fuzzing(args.threads, args.timeout, args.output_file)

        # JS-based endpoint discovery on top of what ffuf found
        if tool.target_url:
            print(f"\n{'─'*80}")
            print("JS FILE DISCOVERY (from HTML responses of found endpoints)")
            print(f"{'─'*80}")
            rp = ResponseParser()
            js_all: Set[str] = set()
            all_eps = list(tool.analyzer.all_endpoints.keys())
            print(f"  Fetching {len(all_eps)} endpoints ({min(args.threads, 100)} workers)…")

            def _fetch_for_js(endpoint: str):
                url = f"{tool.target_url}/{endpoint}"
                status, content = rp.fetch_endpoint(url, 'GET', args.timeout, retries=args.retry)
                return status, content, url

            with ThreadPoolExecutor(max_workers=min(args.threads, 100)) as pool:
                futures = [pool.submit(_fetch_for_js, ep) for ep in all_eps]
                for future in as_completed(futures):
                    status, content, url = future.result()
                    if status and content:
                        found = rp.discover_endpoints_from_js_files(
                            content, url, args.timeout, args.js_workers
                        )
                        js_all.update(found)

            if js_all:
                js_dict = {ep: {'GET'} for ep in js_all}
                tool.analyzer.add_endpoints(js_dict, 'js_discovery')
                print(f"  JS discovery added {len(js_all)} additional endpoints")

        # Path-parameter discovery
        if not args.no_path_params and tool.target_url:
            print(f"\n{'─'*80}")
            print("PATH PARAMETER DISCOVERY")
            print(f"{'─'*80}")
            prober = PathParamProber(tool.target_url, timeout=args.timeout,
                                     retries=args.retry, max_workers=args.js_workers)
            path_hits = prober.probe_all(tool.analyzer.all_endpoints)
            for norm_path, meta in path_hits.items():
                tool.analyzer.add_endpoints({norm_path: meta['methods']}, 'path_param')
                schema = PathParamProber.openapi_schema_for(meta['param_type'], meta['param_format'])
                for m in meta['methods']:
                    tool.analyzer.add_endpoint_parameters(
                        meta['original_endpoint'], m,
                        {'path': {meta['param_name']: schema}, 'query': {}, 'body': {}, 'formData': {}}
                    )
        tool.analyze_ffuf_directories(*args.dirs)

    if args.analyze_html is not None:
        tool.analyze_html_files(args.analyze_html)

    # Parameter fuzzing
    if tool.fuzzer:
        run_param_fuzzing(tool.analyzer, tool.fuzzer)

    tool.print_summary()
    tool.save_results(args.output, args.json)

    if args.openapi:
        tool.analyzer.export_openapi_spec(
            args.openapi, args.api_title, args.api_version,
            args.target or "http://127.0.0.1:5000"
        )
        print(f"OpenAPI spec → {args.openapi}")


if __name__ == "__main__":
    main()
