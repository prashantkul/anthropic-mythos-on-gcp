FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y gcc python3 xxd file gdb && \
    rm -rf /var/lib/apt/lists/*

COPY src/ /target/src/

RUN mkdir -p /target/bin && \
    gcc -fsanitize=address -g -O1 -o /target/bin/canary /target/src/canary.c

RUN useradd -u 1000 -m agent
USER agent
CMD ["/bin/bash"]
