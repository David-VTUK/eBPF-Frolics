# Use an official Ubuntu base image
FROM ubuntu:latest

# Avoid prompts from apt
ENV DEBIAN_FRONTEND=noninteractive

# Install sudo
RUN apt-get update && apt-get install -y sudo

# Create a new user "vscode" and add them to the sudo group
RUN useradd -m vscode && echo "vscode:vscode" | chpasswd && adduser vscode sudo

# Give "vscode" passwordless sudo privileges
RUN echo 'vscode ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers

# Switch to your new user in the docker image
USER vscode

# Set the working directory
WORKDIR /home/vscode