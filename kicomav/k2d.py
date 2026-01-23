# -*- coding:utf-8 -*-
# Author: Kei Choi(hanul93@gmail.com)

"""
KicomAV Daemon (k2d)

This is the main entry point for the KicomAV daemon server.
It provides both REST API and socket protocol interfaces for
antivirus scanning operations.

Usage:
    k2d                           # Start with default settings
    k2d --http-only               # Start REST API server only
    k2d --socket-only             # Start socket server only
    k2d --http-port 8080          # Custom HTTP port
    k2d --generate-key            # Generate API key
"""

import argparse
import asyncio
import logging
import os
import signal
import sys
import threading
from typing import Optional

# Ensure project root is in sys.path for development mode
_k2d_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(_k2d_dir)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from kicomav import __version__ as KICOMAV_VERSION
from kicomav.daemon.config import (
    DaemonConfig,
    get_daemon_config,
    set_daemon_config,
)
from kicomav.daemon.scanner import get_scanner

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def print_banner():
    """Print the daemon banner."""
    print("=" * 60)
    print(f"KicomAV Daemon (k2d) v{KICOMAV_VERSION}")
    print("=" * 60)


def check_dependencies() -> bool:
    """Check if required dependencies are installed.

    Returns:
        True if all dependencies are available
    """
    missing = []

    try:
        import fastapi
    except ImportError:
        missing.append("fastapi")

    try:
        import uvicorn
    except ImportError:
        missing.append("uvicorn")

    if missing:
        print("Error: Missing required dependencies:", ", ".join(missing))
        print()
        print("Install with: pip install kicomav[daemon]")
        print("Or: pip install fastapi uvicorn python-multipart")
        return False

    return True


def generate_api_key() -> str:
    """Generate a new API key.

    Returns:
        Generated API key
    """
    config = get_daemon_config()
    key = config.generate_api_key()
    return key


def write_pid_file(pid_file: str) -> None:
    """Write PID to file.

    Args:
        pid_file: Path to PID file
    """
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))
    logger.info("PID file written: %s", pid_file)


def remove_pid_file(pid_file: str) -> None:
    """Remove PID file.

    Args:
        pid_file: Path to PID file
    """
    try:
        os.unlink(pid_file)
        logger.info("PID file removed: %s", pid_file)
    except OSError:
        pass


def run_http_server(config: DaemonConfig) -> None:
    """Run the HTTP REST API server.

    Args:
        config: Daemon configuration
    """
    from kicomav.daemon.api import create_api_app

    import uvicorn

    app = create_api_app()

    uvicorn.run(
        app,
        host=config.http_host,
        port=config.http_port,
        log_level="info",
    )


async def run_socket_server_async(config: DaemonConfig) -> None:
    """Run the socket server.

    Args:
        config: Daemon configuration
    """
    from kicomav.daemon.socket_server import run_socket_server

    await run_socket_server()


def run_socket_server(config: DaemonConfig) -> None:
    """Run the socket server (sync wrapper).

    Args:
        config: Daemon configuration
    """
    asyncio.run(run_socket_server_async(config))


def run_both_servers(config: DaemonConfig) -> None:
    """Run both HTTP and socket servers.

    Args:
        config: Daemon configuration
    """
    from kicomav.daemon.api import create_api_app
    from kicomav.daemon.socket_server import SocketServer
    from kicomav.daemon.scanner import get_scanner

    import uvicorn

    # Initialize scanner once (shared between servers)
    scanner = get_scanner()
    if not scanner.initialize():
        logger.error("Failed to initialize scanner")
        return

    # Create socket server
    socket_server = SocketServer()

    # Run socket server in a separate thread
    async def start_socket():
        if config.socket_enabled:
            await socket_server.start_tcp("0.0.0.0", config.socket_port)
            if sys.platform != "win32":
                await socket_server.start_unix(config.socket_path)
            await socket_server.serve_forever()

    socket_thread = threading.Thread(
        target=lambda: asyncio.run(start_socket()),
        daemon=True,
    )
    socket_thread.start()
    logger.info("Socket server started in background thread")

    # Run HTTP server in main thread (blocking)
    try:
        from kicomav.daemon.api import create_api_app
        import uvicorn

        # Create a custom app that doesn't initialize scanner again
        from fastapi import FastAPI
        from kicomav.daemon.api import (
            PingResponse,
            VersionResponse,
            StatsResponse,
            ScanResultResponse,
            ScanPathRequest,
            ScanPathResponse,
            ScanStreamRequest,
            ReloadResponse,
            ErrorResponse,
        )
        from kicomav.daemon.auth import get_api_key_dependency
        from fastapi import Depends, File, HTTPException, Query, UploadFile, status
        import base64
        import time
        from kicomav.daemon.scanner import ScanStatus

        app = FastAPI(
            title="KicomAV Daemon API",
            description="REST API for KicomAV antivirus scanning",
            version="1.0.0",
        )

        verify_api_key = get_api_key_dependency()

        @app.get("/ping", response_model=PingResponse, tags=["Health"])
        async def ping():
            if not scanner.is_running():
                raise HTTPException(status_code=503, detail="Scanner not running")
            return PingResponse()

        @app.get("/version", response_model=VersionResponse, tags=["Info"])
        async def version():
            info = scanner.get_version()
            return VersionResponse(**info.to_dict())

        @app.get("/stats", response_model=StatsResponse, tags=["Info"])
        async def stats():
            stat = scanner.get_stats()
            return StatsResponse(**stat.to_dict())

        @app.post("/scan/file", response_model=ScanResultResponse, tags=["Scan"])
        async def scan_file(
            file: UploadFile = File(...),
            include_hash: bool = Query(False),
            api_key: str = Depends(verify_api_key),
        ):
            if file.size and file.size > config.max_upload_size:
                raise HTTPException(status_code=413, detail="File too large")
            content = await file.read()
            if len(content) > config.max_upload_size:
                raise HTTPException(status_code=413, detail="File too large")
            result = scanner.scan_stream(content, file.filename or "uploaded_file")
            return ScanResultResponse(
                filename=result.filename,
                status=result.status.value,
                malware=result.malware_name,
                scan_time_ms=result.scan_time_ms,
                error=result.error_message,
                sha256=result.sha256 if include_hash else None,
            )

        @app.post("/scan/path", response_model=ScanPathResponse, tags=["Scan"])
        async def scan_path(request: ScanPathRequest, api_key: str = Depends(verify_api_key)):
            if not os.path.exists(request.path):
                raise HTTPException(status_code=404, detail="Path not found")
            start_time = time.time()
            if os.path.isfile(request.path):
                result = scanner.scan_file(request.path, include_hash=request.include_hash)
                results = [result]
            else:
                results = scanner.scan_directory(request.path, recursive=request.recursive)
            elapsed_ms = int((time.time() - start_time) * 1000)
            infected = sum(1 for r in results if r.status == ScanStatus.INFECTED)
            errors = sum(1 for r in results if r.status == ScanStatus.ERROR)
            return ScanPathResponse(
                path=request.path,
                files_scanned=len(results),
                infected=infected,
                errors=errors,
                results=[
                    ScanResultResponse(
                        filename=r.filename,
                        status=r.status.value,
                        malware=r.malware_name,
                        scan_time_ms=r.scan_time_ms,
                        error=r.error_message,
                        sha256=r.sha256,
                    )
                    for r in results
                ],
                scan_time_ms=elapsed_ms,
            )

        @app.post("/scan/stream", response_model=ScanResultResponse, tags=["Scan"])
        async def scan_stream(request: ScanStreamRequest, api_key: str = Depends(verify_api_key)):
            try:
                data = base64.b64decode(request.data)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Invalid base64: {e}")
            if len(data) > config.max_upload_size:
                raise HTTPException(status_code=413, detail="Data too large")
            result = scanner.scan_stream(data, request.filename)
            return ScanResultResponse(
                filename=result.filename,
                status=result.status.value,
                malware=result.malware_name,
                scan_time_ms=result.scan_time_ms,
                error=result.error_message,
                sha256=result.sha256,
            )

        @app.post("/reload", response_model=ReloadResponse, tags=["Management"])
        async def reload_signatures(api_key: str = Depends(verify_api_key)):
            success = scanner.reload_signatures()
            return ReloadResponse(success=success, message="Reloaded" if success else "Failed")

        uvicorn.run(
            app,
            host=config.http_host,
            port=config.http_port,
            log_level="info",
        )

    finally:
        scanner.shutdown()


def parse_args() -> argparse.Namespace:
    """Parse command line arguments.

    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="KicomAV Daemon - Antivirus scanning server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  k2d                           Start with default settings
  k2d --http-only               Start REST API server only
  k2d --socket-only             Start socket server only
  k2d --http-port 8080          Custom HTTP port
  k2d --generate-key            Generate API key

Environment variables:
  K2D_HTTP_ENABLED              Enable HTTP server (default: true)
  K2D_HTTP_HOST                 HTTP bind address (default: 127.0.0.1)
  K2D_HTTP_PORT                 HTTP port (default: 8311)
  K2D_SOCKET_ENABLED            Enable socket server (default: true)
  K2D_SOCKET_PORT               Socket port (default: 3311)
  K2D_MAX_UPLOAD_SIZE           Max upload size in bytes (default: 52428800)
  K2D_MAX_WORKERS               Max concurrent workers (default: CPU count)
  K2D_API_KEY                   API key for authentication
  K2D_REQUIRE_AUTH              Require authentication (default: false)
""",
    )

    # Server mode
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--http-only",
        action="store_true",
        help="Run HTTP REST API server only",
    )
    mode_group.add_argument(
        "--socket-only",
        action="store_true",
        help="Run socket server only",
    )

    # HTTP options
    parser.add_argument(
        "--http-host",
        metavar="HOST",
        help="HTTP server bind address",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        metavar="PORT",
        help="HTTP server port",
    )

    # Socket options
    parser.add_argument(
        "--socket-port",
        type=int,
        metavar="PORT",
        help="Socket server port",
    )
    parser.add_argument(
        "--socket-path",
        metavar="PATH",
        help="Unix socket path",
    )

    # Resource options
    parser.add_argument(
        "--workers",
        type=int,
        metavar="N",
        help="Maximum concurrent workers",
    )
    parser.add_argument(
        "--max-size",
        type=int,
        metavar="BYTES",
        help="Maximum upload size in bytes",
    )

    # Authentication
    parser.add_argument(
        "--api-key",
        metavar="KEY",
        help="Set API key for authentication",
    )
    parser.add_argument(
        "--require-auth",
        action="store_true",
        help="Require authentication for API access",
    )
    parser.add_argument(
        "--generate-key",
        action="store_true",
        help="Generate a new API key and exit",
    )

    # Daemon options
    parser.add_argument(
        "--pid-file",
        metavar="PATH",
        help="PID file path",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        help="Log file path",
    )

    # Misc
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"KicomAV Daemon v{KICOMAV_VERSION}",
    )

    return parser.parse_args()


def apply_args_to_config(args: argparse.Namespace, config: DaemonConfig) -> DaemonConfig:
    """Apply command line arguments to configuration.

    Args:
        args: Parsed arguments
        config: Base configuration

    Returns:
        Updated configuration
    """
    if args.http_only:
        config.socket_enabled = False
    if args.socket_only:
        config.http_enabled = False

    if args.http_host:
        config.http_host = args.http_host
    if args.http_port:
        config.http_port = args.http_port
    if args.socket_port:
        config.socket_port = args.socket_port
    if args.socket_path:
        config.socket_path = args.socket_path
    if args.workers:
        config.max_workers = args.workers
    if args.max_size:
        config.max_upload_size = args.max_size
    if args.api_key:
        config.api_key = args.api_key
    if args.require_auth:
        config.require_auth = True
    if args.pid_file:
        config.pid_file = args.pid_file
    if args.log_file:
        config.log_file = args.log_file

    return config


def main() -> int:
    """Main entry point.

    Returns:
        Exit code
    """
    args = parse_args()

    # Handle generate-key
    if args.generate_key:
        key = generate_api_key()
        print("Generated API key:", key)
        print()
        print("Add to your .env file:")
        print(f"  K2D_API_KEY={key}")
        print("  K2D_REQUIRE_AUTH=true")
        return 0

    # Check dependencies
    if not check_dependencies():
        return 1

    # Print banner
    print_banner()

    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Get and update configuration
    config = get_daemon_config()
    config = apply_args_to_config(args, config)
    set_daemon_config(config)

    # Validate configuration
    errors = config.validate()
    if errors:
        for error in errors:
            logger.error("Configuration error: %s", error)
        return 1

    # Setup log file
    if config.log_file:
        file_handler = logging.FileHandler(config.log_file)
        file_handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
        logging.getLogger().addHandler(file_handler)

    # Write PID file
    if config.pid_file:
        write_pid_file(config.pid_file)

    # Print configuration
    logger.info("Configuration:")
    if config.http_enabled:
        logger.info("  HTTP API: http://%s:%d", config.http_host, config.http_port)
    if config.socket_enabled:
        logger.info("  Socket: port %d", config.socket_port)
        if sys.platform != "win32":
            logger.info("  Unix Socket: %s", config.socket_path)
    logger.info("  Max workers: %d", config.max_workers)
    logger.info("  Max upload: %.1f MB", config.max_upload_size_mb)
    logger.info("  Auth required: %s", config.require_auth)

    # Setup signal handlers
    def signal_handler(signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        if config.pid_file:
            remove_pid_file(config.pid_file)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run servers
    try:
        if args.http_only:
            run_http_server(config)
        elif args.socket_only:
            run_socket_server(config)
        else:
            run_both_servers(config)
    except KeyboardInterrupt:
        logger.info("Interrupted, shutting down...")
    except Exception as e:
        logger.exception("Fatal error: %s", e)
        return 1
    finally:
        if config.pid_file:
            remove_pid_file(config.pid_file)

    return 0


if __name__ == "__main__":
    sys.exit(main())
