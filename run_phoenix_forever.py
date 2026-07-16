import os
import time

import phoenix as px

port = int(os.getenv("PORT", os.getenv("PHOENIX_PORT", "7007")))
host = os.getenv("PHOENIX_HOST", "0.0.0.0")

# Render provides PORT; bind Phoenix explicitly so it can route traffic.
try:
    px.launch_app(host=host, port=port)
except TypeError:
    # Compatibility fallback for older Phoenix versions.
    px.launch_app(port=port)

print(f"Phoenix ready on http://{host}:{port}")

while True:
    time.sleep(3600)
