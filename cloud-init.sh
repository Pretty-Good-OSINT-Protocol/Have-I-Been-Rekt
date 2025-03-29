
#!/bin/bash
# cloud-init.sh for deploying Pretty Good OSINT Protocol (PGOP)

# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker and Docker Compose
sudo apt install -y docker.io docker-compose git

# Enable Docker service
sudo systemctl enable docker
sudo systemctl start docker

# Clone PGOP repo (placeholder URL - replace with actual GitHub repo)
cd /opt
sudo git clone https://github.com/your-username/Pretty-Good-OSINT-Protocol.git pgop
cd pgop

# Optional: Pull updated code if this is reused
# sudo git pull

# Build and run the Docker container
sudo docker-compose up -d --build

echo "PGOP deployed. Visit http://<your-vm-ip>:8501 to access 'Have I Been Rekt'"
