"""Entry point for packet-mapper."""

import argparse
import logging


def main():
    parser = argparse.ArgumentParser(description="packet-mapper: live network connection map")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument(
        "--iface", default=None, help="Network interface to sniff (default: auto)"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.iface:
        import os

        os.environ["PACKET_MAPPER_IFACE"] = args.iface

    import uvicorn

    uvicorn.run(
        "packet_mapper.api:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level="debug" if args.debug else "info",
    )


if __name__ == "__main__":
    main()
