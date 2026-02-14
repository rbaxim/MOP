"""
hello? did you forget about me. pls go to /mop/hello.
trust its very cool
"""

import sys

sys.stdout.write(
    '{"content":"Hello World","status":200,"headers":{"Content-Type":"text/plain"}}'
)
sys.stdout.flush()