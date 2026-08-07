"""
Usage (run from the backend/ folder):
    python -m scripts.create_api_key "backend-internal"
"""
import asyncio
import sys

sys.path.insert(0, ".")

from database.mongo import create_indexes
from services.api_key_service import create_api_key


async def main(name: str):
    await create_indexes()
    key = await create_api_key(name)
    print("\nAPI key created successfully.")
    print(f"  Name:   {name}")
    print(f"  Key:    {key}")
    print("\nStore this key somewhere safe. It will NOT be shown again.\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m scripts.create_api_key <key-name>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
