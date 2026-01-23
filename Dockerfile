# Use official Python 3.13 slim image
FROM python:3.13-slim

# Set working directory inside container
WORKDIR /moapy

VOLUME ["/moapy/moppy"] 
VOLUME ["/moapy/scripts"]

# Copy your project files
COPY . /moapy

RUN apt-get update
RUN apt-get update && apt-get install -y \
    curl \
    python3-venv \
    python3-pip \
    build-essential \
    libssl-dev \
    libffi-dev 

RUN curl -LsSf https://astral.sh/uv/install.sh | sh

ENV PATH="/root/.local/bin:$PATH"

RUN uv venv

# Expose port for MOP server (example: 8080)
EXPOSE 8080
EXPOSE 8000

# Set default command
ENTRYPOINT ["/root/.local/bin/uv", "run", "mop.py"]

CMD ["--port", "8000", "--force-port"]
