# Use official Python 3.13 slim image
FROM python:3.13-slim

# Set working directory inside container
WORKDIR /moapy

VOLUME ["/moapy/moppy"] 
VOLUME ["/moapy/scripts"]


# Copy your project files
COPY . /moapy

RUN apt-get update && apt-get install -y \
    curl \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh

HEALTHCHECK CMD bash -c '\
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/mop/process || curl -s -o /dev/null -w "%{http_code}" -k https://localhost:8000/mop/process); \
    if [ "$STATUS" -eq 200 ] || [ "$STATUS" -eq 428 ]; then exit 0; else exit 1; fi'


ENV PATH="/root/.local/bin:$PATH"

# No MOP, you must serve on 0.0.0.0
ENV AM_I_IN_A_DOCKER_CONTAINER=true

# Python 3.13 slim image is unix-like. Save time
RUN uv sync --frozen --no-dev --group unix

# Expose port for MOP server (example: 8080)
EXPOSE 8080
EXPOSE 8000

# Set default command
ENTRYPOINT ["/root/.local/bin/uv", "run", "mop.py"]

CMD ["--port", "8000", "--force-port", "--host", "0.0.0.0"]