#!/usr/bin/env python3
"""Debug what self._ix.list() actually returns"""
import os
from dotenv import load_dotenv
from pinecone import Pinecone

load_dotenv()

pc = Pinecone(api_key=os.getenv("PINECONE_API_KEY"))
index = pc.Index(name=os.getenv("PINECONE_INDEX", "ragpii-384"))

print("Testing index.list()...")
print(f"Index name: {os.getenv('PINECONE_INDEX')}")

# Try different approaches
print("\n1. list() with no namespace:")
try:
    result = list(index.list())
    print(f"   Result type: {type(result)}, Length: {len(result)}")
    print(f"   First 3 items: {result[:3]}")
except Exception as e:
    print(f"   Error: {e}")

print("\n2. list() with namespace='':")
try:
    result = list(index.list(namespace=''))
    print(f"   Result type: {type(result)}, Length: {len(result)}")
    if result:
        print(f"   First 3 items: {result[:3]}")
except Exception as e:
    print(f"   Error: {e}")

print("\n3. list() with None namespace:")
try:
    result = list(index.list(namespace=None))
    print(f"   Result type: {type(result)}, Length: {len(result)}")
    if result:
        print(f"   First 3 items: {result[:3]}")
except Exception as e:
    print(f"   Error: {e}")

print("\n4. list() generator (first 5 pages):")
try:
    pages = index.list()
    for i, page in enumerate(pages):
        if i < 5:
            print(f"   Page {i}: type={type(page)}, len={len(page) if hasattr(page, '__len__') else 'N/A'}, content={page[:3] if hasattr(page, '__getitem__') else page}")
        else:
            break
except Exception as e:
    print(f"   Error: {e}")

print("\n5. Testing fetch with specific IDs:")
try:
    # Try to get at least one ID from list
    list_gen = index.list()
    first_page = next(list_gen, None)
    if first_page:
        print(f"   Got first page: {first_page[:3] if len(first_page) > 0 else 'empty'}")
        fetched = index.fetch(ids=list(first_page)[:5])
        print(f"   Fetch result: {fetched}")
except Exception as e:
    print(f"   Error: {e}")
