# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Client (k2c)

Command-line client for communicating with the KicomAV daemon (k2d).
Supports both REST API and socket protocol.

Usage:
    k2c path[s]                    # Scan files/directories
    k2c --stream < file            # Scan from stdin
    k2c --ping                     # Check server status
    k2c --version                  # Get server version
    k2c --stats                    # Get server statistics
"""

import argparse
import base64
import json
import os
import socket
import struct
import sys
import time
from typing import List, Optional, Tuple

# Ensure project root is in sys.path for development mode
_k2c_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_k2c_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from kicomav import __version__ as KICOMAV_VERSION

# Default connection settings
DEFAULT_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8311
DEFAULT_SOCKET_PORT = 3311


class K2Client:
    """Client for communicating with k2d daemon."""

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        http_port: int = DEFAULT_HTTP_PORT,
        socket_port: int = DEFAULT_SOCKET_PORT,
        use_socket: bool = False,
        api_key: Optional[str] = None,
        timeout: int = 300,
    ):
        self.host = host
        self.http_port = http_port
        self.socket_port = socket_port
        self.use_socket = use_socket
        self.api_key = api_key
        self.timeout = timeout

    def _http_request(
        self,
        method: str,
        endpoint: str,
        data: Optional[dict] = None,
        files: Optional[dict] = None,
    ) -> Tuple[bool, dict]:
        """Make HTTP request to REST API."""
        try:
            import urllib.request
            import urllib.error

            url = f"http://{self.host}:{self.http_port}{endpoint}"
            headers = {}

            if self.api_key:
                headers["X-API-Key"] = self.api_key

            if files:
                # Multipart form data for file upload
                boundary = "----K2ClientBoundary"
                body = b""

                for field_name, (filename, content) in files.items():
                    body += f"--{boundary}\r\n".encode()
                    body += f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode()
                    body += b"Content-Type: application/octet-stream\r\n\r\n"
                    body += content
                    body += b"\r\n"

                body += f"--{boundary}--\r\n".encode()
                headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"

                req = urllib.request.Request(url, data=body, headers=headers, method=method)

            elif data:
                headers["Content-Type"] = "application/json"
                body = json.dumps(data).encode("utf-8")
                req = urllib.request.Request(url, data=body, headers=headers, method=method)
            else:
                req = urllib.request.Request(url, headers=headers, method=method)

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
                return True, result

        except urllib.error.HTTPError as e:
            try:
                error_body = json.loads(e.read().decode("utf-8"))
                return False, {"error": error_body.get("detail", str(e))}
            except Exception:
                return False, {"error": str(e)}
        except urllib.error.URLError as e:
            return False, {"error": f"Connection failed: {e.reason}"}
        except Exception as e:
            return False, {"error": str(e)}

    def _socket_command(self, command: str) -> Tuple[bool, str]:
        """Send command via socket protocol."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.socket_port))

            # Send AUTH if api_key provided
            if self.api_key:
                sock.send(f"AUTH {self.api_key}\n".encode())
                response = sock.recv(4096).decode().strip()
                if "FAILED" in response:
                    sock.close()
                    return False, "Authentication failed"

            sock.send(f"{command}\n".encode())
            response = sock.recv(65536).decode().strip()
            sock.close()

            return True, response

        except socket.timeout:
            return False, "Connection timeout"
        except ConnectionRefusedError:
            return False, "Connection refused - is k2d running?"
        except Exception as e:
            return False, str(e)

    def _socket_instream(self, data: bytes, filename: str = "stream") -> Tuple[bool, str]:
        """Send INSTREAM command via socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.socket_port))

            # Send AUTH if api_key provided
            if self.api_key:
                sock.send(f"AUTH {self.api_key}\n".encode())
                response = sock.recv(4096).decode().strip()
                if "FAILED" in response:
                    sock.close()
                    return False, "Authentication failed"

            # Send INSTREAM command
            sock.send(b"INSTREAM\n")
            time.sleep(0.1)  # Wait for server to process command

            # Send data in chunks
            chunk_size = 8192
            for i in range(0, len(data), chunk_size):
                chunk = data[i : i + chunk_size]
                sock.send(struct.pack("!I", len(chunk)) + chunk)

            # Send terminator
            sock.send(struct.pack("!I", 0))

            # Get response
            response = sock.recv(4096).decode().strip()
            sock.close()

            return True, response

        except socket.timeout:
            return False, "Connection timeout"
        except ConnectionRefusedError:
            return False, "Connection refused - is k2d running?"
        except Exception as e:
            return False, str(e)

    def ping(self) -> Tuple[bool, str]:
        """Check if server is running."""
        if self.use_socket:
            return self._socket_command("PING")
        else:
            success, result = self._http_request("GET", "/ping")
            if success:
                return True, result.get("message", "pong")
            return False, result.get("error", "Unknown error")

    def version(self) -> Tuple[bool, dict]:
        """Get server version info."""
        if self.use_socket:
            success, response = self._socket_command("VERSION")
            if success:
                return True, {"version": response}
            return False, {"error": response}
        else:
            return self._http_request("GET", "/version")

    def stats(self) -> Tuple[bool, dict]:
        """Get server statistics."""
        if self.use_socket:
            success, response = self._socket_command("STATS")
            if success:
                return True, {"stats": response}
            return False, {"error": response}
        else:
            return self._http_request("GET", "/stats")

    def scan_file(self, filepath: str) -> Tuple[bool, dict]:
        """Scan a single file."""
        filepath = os.path.abspath(filepath)

        if self.use_socket:
            success, response = self._socket_command(f"SCAN {filepath}")
            if success:
                # Parse socket response
                if "FOUND" in response:
                    parts = response.rsplit(":", 1)
                    malware = parts[1].replace("FOUND", "").strip() if len(parts) > 1 else "Unknown"
                    return True, {
                        "filename": filepath,
                        "status": "infected",
                        "malware": malware,
                    }
                elif "OK" in response:
                    return True, {"filename": filepath, "status": "clean"}
                elif "ERROR" in response:
                    return True, {
                        "filename": filepath,
                        "status": "error",
                        "error": response,
                    }
                return True, {"filename": filepath, "status": "unknown", "raw": response}
            return False, {"error": response}
        else:
            # Read file and send via API
            try:
                with open(filepath, "rb") as f:
                    content = f.read()
                filename = os.path.basename(filepath)
                return self._http_request(
                    "POST",
                    "/scan/file",
                    files={"file": (filename, content)},
                )
            except FileNotFoundError:
                return False, {"error": f"File not found: {filepath}"}
            except PermissionError:
                return False, {"error": f"Permission denied: {filepath}"}
            except Exception as e:
                return False, {"error": str(e)}

    def scan_path(self, path: str, recursive: bool = True) -> Tuple[bool, dict]:
        """Scan a path (file or directory) on the server."""
        path = os.path.abspath(path)

        if self.use_socket:
            command = "CONTSCAN" if recursive else "SCAN"
            success, response = self._socket_command(f"{command} {path}")
            if success:
                # Parse multi-line response
                results = []
                for line in response.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    if "FOUND" in line:
                        parts = line.rsplit(":", 1)
                        filepath = parts[0].strip()
                        malware = parts[1].replace("FOUND", "").strip() if len(parts) > 1 else "Unknown"
                        results.append(
                            {
                                "filename": filepath,
                                "status": "infected",
                                "malware": malware,
                            }
                        )
                    elif "OK" in line:
                        parts = line.rsplit(":", 1)
                        filepath = parts[0].strip()
                        results.append({"filename": filepath, "status": "clean"})
                    elif "ERROR" in line:
                        parts = line.rsplit(":", 1)
                        filepath = parts[0].strip()
                        results.append(
                            {
                                "filename": filepath,
                                "status": "error",
                                "error": line,
                            }
                        )

                infected = sum(1 for r in results if r.get("status") == "infected")
                return True, {
                    "path": path,
                    "files_scanned": len(results),
                    "infected": infected,
                    "results": results,
                }
            return False, {"error": response}
        else:
            return self._http_request(
                "POST",
                "/scan/path",
                data={"path": path, "recursive": recursive},
            )

    def scan_stream(self, data: bytes, filename: str = "stream") -> Tuple[bool, dict]:
        """Scan data from stream."""
        if self.use_socket:
            success, response = self._socket_instream(data, filename)
            if success:
                if "FOUND" in response:
                    parts = response.rsplit(":", 1)
                    malware = parts[1].replace("FOUND", "").strip() if len(parts) > 1 else "Unknown"
                    return True, {
                        "filename": filename,
                        "status": "infected",
                        "malware": malware,
                    }
                elif "OK" in response:
                    return True, {"filename": filename, "status": "clean"}
                return True, {"filename": filename, "status": "unknown", "raw": response}
            return False, {"error": response}
        else:
            encoded = base64.b64encode(data).decode("utf-8")
            return self._http_request(
                "POST",
                "/scan/stream",
                data={"data": encoded, "filename": filename},
            )

    def reload(self) -> Tuple[bool, str]:
        """Reload signatures on server."""
        if self.use_socket:
            return self._socket_command("RELOAD")
        else:
            success, result = self._http_request("POST", "/reload")
            if success:
                return True, result.get("message", "Reloaded")
            return False, result.get("error", "Unknown error")


def print_banner():
    """Print client banner."""
    print("=" * 60)
    print(f"KicomAV Client (k2c) v{KICOMAV_VERSION}")
    print("=" * 60)


def print_result(result: dict, json_output: bool = False, quiet: bool = False):
    """Print scan result."""
    if json_output:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    status = result.get("status", "unknown")
    filename = result.get("filename", "unknown")

    if quiet and status == "clean":
        return

    if status == "infected":
        malware = result.get("malware", "Unknown")
        print(f"{filename}  infected : {malware}")
    elif status == "clean":
        print(f"{filename}  ok")
    elif status == "error":
        error = result.get("error", "Unknown error")
        print(f"{filename}  error : {error}")
    else:
        print(f"{filename}  {status}")


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="KicomAV Client - Connect to k2d daemon for scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  k2c /path/to/file              Scan a file
  k2c /path/to/folder            Scan a directory
  k2c --stream < suspicious.exe  Scan from stdin
  k2c --ping                     Check server status
  k2c --version                  Get server version
  k2c --stats                    Get statistics

Connection:
  k2c --host 192.168.1.100 /path   Connect to remote server
  k2c --socket /path               Use socket protocol instead of REST
""",
    )

    # Scan targets
    parser.add_argument(
        "paths",
        nargs="*",
        help="Files or directories to scan",
    )

    # Server commands
    server_group = parser.add_argument_group("Server commands")
    server_group.add_argument(
        "--ping",
        action="store_true",
        help="Check if server is running",
    )
    server_group.add_argument(
        "--version",
        action="store_true",
        dest="server_version",
        help="Get server version info",
    )
    server_group.add_argument(
        "--stats",
        action="store_true",
        help="Get server statistics",
    )
    server_group.add_argument(
        "--reload",
        action="store_true",
        help="Reload signatures on server",
    )

    # Scan options
    scan_group = parser.add_argument_group("Scan options")
    scan_group.add_argument(
        "--stream",
        action="store_true",
        help="Read data from stdin",
    )
    scan_group.add_argument(
        "-R",
        "--no-recursive",
        action="store_true",
        help="Do not scan subdirectories",
    )
    scan_group.add_argument(
        "--exclude",
        action="append",
        metavar="PATTERN",
        default=[],
        help="Exclude files matching pattern (can be repeated)",
    )
    scan_group.add_argument(
        "--exclude-ext",
        metavar="EXT",
        help="Exclude file extensions (comma-separated)",
    )
    scan_group.add_argument(
        "--max-size",
        metavar="SIZE",
        help="Skip files larger than SIZE (e.g., 100MB)",
    )
    scan_group.add_argument(
        "--ignore-file",
        metavar="FILE",
        help="Load exclusion rules from file",
    )

    # Connection options
    conn_group = parser.add_argument_group("Connection options")
    conn_group.add_argument(
        "--host",
        default=DEFAULT_HOST,
        metavar="HOST",
        help=f"Server host (default: {DEFAULT_HOST})",
    )
    conn_group.add_argument(
        "--port",
        type=int,
        metavar="PORT",
        help="Server port",
    )
    conn_group.add_argument(
        "--socket",
        action="store_true",
        help="Use socket protocol instead of REST API",
    )
    conn_group.add_argument(
        "--api-key",
        metavar="KEY",
        help="API key for authentication",
    )
    conn_group.add_argument(
        "--timeout",
        type=int,
        default=300,
        metavar="SEC",
        help="Connection timeout in seconds (default: 300)",
    )

    # Output options
    output_group = parser.add_argument_group("Output options")
    output_group.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )
    output_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Only show infected files",
    )
    output_group.add_argument(
        "--no-banner",
        action="store_true",
        help="Don't print banner",
    )
    output_group.add_argument(
        "--report",
        metavar="FORMAT",
        help="Generate report (json, html)",
    )

    # Cache options
    cache_group = parser.add_argument_group("Cache options")
    cache_group.add_argument(
        "--cache-clear",
        action="store_true",
        help="Clear the scan cache",
    )
    cache_group.add_argument(
        "--cache-stats",
        action="store_true",
        help="Show scan cache statistics",
    )
    cache_group.add_argument(
        "--cache-expire",
        type=int,
        default=7,
        metavar="DAYS",
        help="Cache expiration in days (default: 7, 0=never)",
    )

    return parser.parse_args()


def setup_client_exclusion_rules(args):
    """Setup exclusion rules from command line options.

    Args:
        args: Parsed command line arguments

    Returns:
        ExclusionRule object or None
    """
    from kicomav.kavcore.k2exclude import ExclusionRule, find_ignore_file

    rule = ExclusionRule()

    # Load from ignore file (--ignore-file option or auto-detect .kicomav-ignore)
    ignore_file = args.ignore_file
    if not ignore_file and args.paths:
        # Auto-detect .kicomav-ignore from scan path
        ignore_file = find_ignore_file(args.paths[0])

    if ignore_file:
        rule.load_from_file(ignore_file)

    # Add patterns from --exclude options
    if args.exclude:
        rule.add_patterns(args.exclude)

    # Add extensions from --exclude-ext option (comma-separated)
    if args.exclude_ext:
        extensions = [ext.strip() for ext in args.exclude_ext.split(",")]
        rule.add_extensions(extensions)

    # Set max size from --max-size option
    if args.max_size:
        if not rule.set_max_size(args.max_size):
            print(f"Warning: Invalid size format: {args.max_size}")

    return rule if not rule.is_empty() else None


def scan_path_with_exclusion(
    client, path: str, recursive: bool, exclusion_rule, quiet: bool, json_output: bool
) -> tuple:
    """Scan a path with exclusion rules applied.

    Args:
        client: K2Client instance
        path: Path to scan
        recursive: Whether to scan recursively
        exclusion_rule: ExclusionRule instance or None
        quiet: Quiet mode
        json_output: JSON output mode

    Returns:
        Tuple of (files_count, infected_count, error_count, excluded_count, results_list)
    """
    import glob

    files_count = 0
    infected_count = 0
    error_count = 0
    excluded_count = 0
    results = []

    path = os.path.abspath(path)

    # If path is a file, scan it directly
    if os.path.isfile(path):
        if exclusion_rule and exclusion_rule.should_exclude(path):
            excluded_count += 1
            return files_count, infected_count, error_count, excluded_count, results

        success, result = client.scan_file(path)
        if success:
            print_result(result, json_output, quiet)
            results.append(result)
            files_count += 1
            if result.get("status") == "infected":
                infected_count += 1
            elif result.get("status") == "error":
                error_count += 1
        else:
            print(f"Error: {result.get('error', 'Unknown error')}")
            error_count += 1
        return files_count, infected_count, error_count, excluded_count, results

    # Directory scan - collect files with exclusion filtering
    files_to_scan = []
    if recursive:
        for root, dirs, files in os.walk(path):
            for f in files:
                filepath = os.path.join(root, f)
                if exclusion_rule and exclusion_rule.should_exclude(filepath):
                    excluded_count += 1
                    continue
                files_to_scan.append(filepath)
    else:
        for f in os.listdir(path):
            filepath = os.path.join(path, f)
            if os.path.isfile(filepath):
                if exclusion_rule and exclusion_rule.should_exclude(filepath):
                    excluded_count += 1
                    continue
                files_to_scan.append(filepath)

    # Scan collected files
    for filepath in files_to_scan:
        success, result = client.scan_file(filepath)
        if success:
            print_result(result, json_output, quiet)
            results.append(result)
            files_count += 1
            if result.get("status") == "infected":
                infected_count += 1
            elif result.get("status") == "error":
                error_count += 1
        else:
            print(f"Error scanning {filepath}: {result.get('error', 'Unknown error')}")
            error_count += 1

    return files_count, infected_count, error_count, excluded_count, results


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Print banner
    if not args.no_banner and not args.json:
        print_banner()
        print()

    # Handle cache commands (local operations, no server connection needed)
    if args.cache_clear:
        return handle_cache_clear(args.json)

    if args.cache_stats:
        return handle_cache_stats(args.cache_expire, args.json)

    # Determine port
    if args.port:
        http_port = args.port
        socket_port = args.port
    else:
        http_port = DEFAULT_HTTP_PORT
        socket_port = DEFAULT_SOCKET_PORT

    # Create client
    client = K2Client(
        host=args.host,
        http_port=http_port,
        socket_port=socket_port,
        use_socket=args.socket,
        api_key=args.api_key,
        timeout=args.timeout,
    )

    # Handle server commands
    if args.ping:
        success, message = client.ping()
        if success:
            if args.json:
                print(json.dumps({"status": "ok", "message": message}))
            else:
                print(f"Server is running: {message}")
            return 0
        else:
            if args.json:
                print(json.dumps({"status": "error", "error": message}))
            else:
                print(f"Error: {message}")
            return 1

    if args.server_version:
        success, result = client.version()
        if success:
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                if isinstance(result.get("version"), str):
                    print(result["version"])
                else:
                    print(f"Version: {result.get('version', 'Unknown')}")
                    print(f"Signatures: {result.get('signatures', 'Unknown')}")
                    print(f"Build Date: {result.get('build_date', 'Unknown')}")
            return 0
        else:
            if args.json:
                print(json.dumps(result))
            else:
                print(f"Error: {result.get('error', 'Unknown error')}")
            return 1

    if args.stats:
        success, result = client.stats()
        if success:
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                if "stats" in result:
                    print(result["stats"])
                else:
                    print(f"Uptime: {result.get('uptime_seconds', 0)}s")
                    print(f"Total Scans: {result.get('scans_total', 0)}")
                    print(f"Files Scanned: {result.get('files_scanned', 0)}")
                    print(f"Malware Found: {result.get('malware_found', 0)}")
                    print(f"Errors: {result.get('errors', 0)}")
            return 0
        else:
            if args.json:
                print(json.dumps(result))
            else:
                print(f"Error: {result.get('error', 'Unknown error')}")
            return 1

    if args.reload:
        success, message = client.reload()
        if success:
            if args.json:
                print(json.dumps({"status": "ok", "message": message}))
            else:
                print(f"Reload: {message}")
            return 0
        else:
            if args.json:
                print(json.dumps({"status": "error", "error": message}))
            else:
                print(f"Error: {message}")
            return 1

    # Handle stream scan
    if args.stream:
        if sys.stdin.isatty():
            print("Error: No data on stdin. Use: k2c --stream < file")
            return 1

        data = sys.stdin.buffer.read()
        success, result = client.scan_stream(data)

        if success:
            print_result(result, args.json, args.quiet)
            return 0 if result.get("status") != "infected" else 1
        else:
            if args.json:
                print(json.dumps(result))
            else:
                print(f"Error: {result.get('error', 'Unknown error')}")
            return 1

    # Handle path scan
    if not args.paths:
        print("Error: No paths specified. Use: k2c /path/to/scan")
        print("       Or use --help for more options")
        return 1

    # Setup exclusion rules
    exclusion_rule = setup_client_exclusion_rules(args)

    total_files = 0
    total_infected = 0
    total_errors = 0
    total_excluded = 0
    all_results = []

    for path in args.paths:
        if not os.path.exists(path):
            print(f"Error: Path not found: {path}")
            total_errors += 1
            continue

        recursive = not args.no_recursive

        # Use exclusion-aware scanning if exclusion rules are set
        if exclusion_rule:
            files, infected, errors, excluded, results = scan_path_with_exclusion(
                client, path, recursive, exclusion_rule, args.quiet, args.json
            )
            total_files += files
            total_infected += infected
            total_errors += errors
            total_excluded += excluded
            all_results.extend(results)
        else:
            # Use server-side scanning without exclusion
            success, result = client.scan_path(path, recursive=recursive)

            if success:
                if "results" in result:
                    # Directory scan
                    for r in result["results"]:
                        print_result(r, args.json, args.quiet)
                        all_results.append(r)
                    total_files += result.get("files_scanned", 0)
                    total_infected += result.get("infected", 0)
                    total_errors += result.get("errors", 0)
                else:
                    # Single file
                    print_result(result, args.json, args.quiet)
                    all_results.append(result)
                    total_files += 1
                    if result.get("status") == "infected":
                        total_infected += 1
                    elif result.get("status") == "error":
                        total_errors += 1
            else:
                if args.json:
                    print(json.dumps(result))
                else:
                    print(f"Error scanning {path}: {result.get('error', 'Unknown error')}")
                total_errors += 1

    # Print summary
    if not args.json and not args.quiet and not args.report and (total_files > 0 or total_excluded > 0):
        print()
        print("-" * 40)
        print(f"Files scanned: {total_files}")
        print(f"Infected: {total_infected}")
        print(f"Errors: {total_errors}")
        if total_excluded > 0:
            print(f"Excluded: {total_excluded}")

    # Generate report if requested
    if args.report and all_results:
        generate_client_report(args, all_results)

    return 1 if total_infected > 0 else 0


def handle_cache_clear(json_output: bool = False) -> int:
    """Clear the scan cache.

    Args:
        json_output: Output in JSON format

    Returns:
        Exit code (0 on success)
    """
    from kicomav.kavcore.k2cache import ScanCache

    cache = ScanCache()
    count = cache.clear()
    cache.vacuum()
    cache.close()

    if json_output:
        print(json.dumps({"status": "ok", "entries_removed": count}))
    else:
        print(f"Cache cleared: {count} entries removed")

    return 0


def handle_cache_stats(expire_days: int = 7, json_output: bool = False) -> int:
    """Show scan cache statistics.

    Args:
        expire_days: Cache expiration in days
        json_output: Output in JSON format

    Returns:
        Exit code (0 on success)
    """
    from kicomav.kavcore.k2cache import ScanCache

    cache = ScanCache(expire_days=expire_days)
    stats = cache.get_stats()
    cache.close()

    if json_output:
        print(json.dumps(stats, indent=2, ensure_ascii=False))
    else:
        print("Scan Cache Statistics")
        print("-" * 40)
        print(f"Cache path: {stats['cache_path']}")
        print(f"Cache size: {stats['cache_size_str']}")
        print(f"Total entries: {stats['total_entries']}")
        print(f"Clean files: {stats['clean_files']}")
        print(f"Infected files: {stats['infected_files']}")
        print(f"Error files: {stats['error_files']}")
        print(f"Expired entries: {stats['expired_entries']}")
        print(f"Expire days: {stats['expire_days']}")
        if stats["oldest_entry"]:
            print(f"Oldest entry: {stats['oldest_entry']}")
        if stats["newest_entry"]:
            print(f"Newest entry: {stats['newest_entry']}")

    return 0


def generate_client_report(args, results: list) -> None:
    """Generate report from scan results."""
    from kicomav.report import ReportGenerator, create_summary_from_results

    report_format = args.report.lower()
    if report_format not in ("json", "html"):
        print(f"Error: Unsupported report format: {report_format}. Use 'json' or 'html'.")
        return

    # Get version info from server
    client = K2Client(
        host=args.host,
        http_port=args.port or DEFAULT_HTTP_PORT,
        socket_port=args.port or DEFAULT_SOCKET_PORT,
        use_socket=args.socket,
    )
    success, version_info = client.version()

    sig_count = 0
    sig_date = ""
    version = KICOMAV_VERSION

    if success and isinstance(version_info, dict):
        sig_count = version_info.get("signatures", 0)
        sig_date = version_info.get("last_update", "")
        version = version_info.get("version", KICOMAV_VERSION)

    # Create summary
    scan_path = ", ".join(args.paths) if args.paths else "Unknown"
    summary = create_summary_from_results(
        scan_path=scan_path,
        results=results,
        kicomav_version=version,
        signature_count=sig_count,
        signature_date=sig_date,
    )

    # Generate report
    generator = ReportGenerator()
    if report_format == "json":
        report = generator.to_json(summary)
    else:
        report = generator.to_html(summary)

    print(report)


if __name__ == "__main__":
    sys.exit(main())
