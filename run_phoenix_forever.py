import os
import subprocess
import sys

port = os.getenv("PORT", os.getenv("PHOENIX_PORT", "6006"))
host = os.getenv("PHOENIX_HOST", "0.0.0.0")

# Render requires binding to its assigned PORT.
os.environ["PHOENIX_PORT"] = str(port)
os.environ["PHOENIX_HOST"] = host

print(f"Starting Phoenix server on http://{host}:{port}")
subprocess.run([sys.executable, "-m", "phoenix.server.main", "serve"], check=True)
