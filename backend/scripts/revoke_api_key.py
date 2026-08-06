"""
Usage (run from the backend/ folder):
    python -m scripts.revoke_api_key "backend-internal"
"""
import asyncio
import sys

sys.path.insert(0, ".")

from services.api_key_service import revoke_api_key


async def main(name_or_prefix: str):
    success = await revoke_api_key(name_or_prefix)
    print("Key revoked." if success else "No matching key found.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m scripts.revoke_api_key <key-name-or-prefix>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
