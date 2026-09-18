import subprocess
import sys
import os

# The directory where the Dockerfile is located (can be your OSS-Fuzz directory)
DOCKERFILE_DIR = os.getenv("DOCKERFILE_DIR", ".")  # Default to the current directory

# The name of the Docker image you want to build
IMAGE_NAME = "oss-fuzz-image"

# Specify the desired platform (in this case, amd64)
PLATFORM = "linux/amd64"

# Docker Buildx setup
DOCKER_BUILDX = "docker buildx"

# Function to run shell commands and capture output
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Command succeeded: {command}")
        return result.stdout.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {command}")
        print(f"Error: {e.stderr.decode('utf-8')}")
        sys.exit(1)

# Function to build Docker image with the --platform=linux/amd64 flag
def build_docker_image():
    print("Building Docker image for platform: amd64...")
    
    # Construct the Docker build command with the --platform flag
    command = f"{DOCKER_BUILDX} build --platform {PLATFORM} -t {IMAGE_NAME} {DOCKERFILE_DIR}"
    
    # Run the command to build the image
    run_command(command)

# Function to list Docker images to confirm the build
def list_docker_images():
    print("Listing Docker images...")
    command = "docker images"
    print(run_command(command))

def main():
    # Build the Docker image with the specified platform
    build_docker_image()

    # Optionally, list the Docker images to confirm the build was successful
    list_docker_images()

    print("Docker image built successfully for platform: amd64")

if __name__ == "__main__":
    main()
