FROM ubuntu:22.04

# Configure environments
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Tokyo

## Disable making coredump
RUN echo "ulimit -Sc 0" >> ~/.bashrc
RUN echo "export IGNOREEOF=2" >> ~/.profile

# Install packages by apt
RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y build-essential cmake less git emacs gdb numactl expect

# Install Microsoft SEAL
RUN mkdir -p /usr/local/src
WORKDIR /usr/local/src
RUN git clone -b 4.1.1 https://github.com/microsoft/SEAL.git
WORKDIR /usr/local/src/SEAL
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF && cmake --build build -j && cmake --install build

# Copy sources
RUN mkdir -p /app/src
COPY . /app/src/

# Add local user
RUN adduser local-user

# Make directory for build
RUN install -o local-user -g local-user -m 755 -d /app/build

# Switch user
USER local-user

# Prepare
WORKDIR /app/src
RUN echo "alias rm='rm -i'" >> ~/.bashrc
RUN echo "export IGNOREEOF=10" >> ~/.profile
RUN echo "export LESSCHARSET=utf-8 " >> ~/.profile

RUN cmake -S . -B /app/build -DCMAKE_BUILD_TYPE=Release
RUN cmake --build /app/build -j


# Execution command
CMD ["/bin/bash"]




