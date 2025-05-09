
#!/bin/bash

# PGOP Automation Script for GitHub + Hugging Face CLI

# Set your variables here (replace with actual values)
GITHUB_USERNAME="your-username"
GITHUB_REPO="Pretty-Good-OSINT-Protocol"
HUGGINGFACE_USERNAME="your-hf-username"
HUGGINGFACE_SPACE="pgop-demo"
HUGGINGFACE_TOKEN="your_hf_token"

# Step 1: Initialize GitHub repo (requires GitHub CLI installed and authenticated)
echo "Creating GitHub repository..."
gh repo create $GITHUB_USERNAME/$GITHUB_REPO --public --confirm

# Step 2: Push project to GitHub
echo "Pushing project to GitHub..."
git init
git remote add origin https://github.com/$GITHUB_USERNAME/$GITHUB_REPO.git
git add .
git commit -m "Initial commit"
git branch -M main
git push -u origin main

# Step 3: Login to Hugging Face CLI
echo "Logging in to Hugging Face CLI..."
huggingface-cli login --token $HUGGINGFACE_TOKEN

# Step 4: Create Hugging Face Space
echo "Creating Hugging Face Space..."
huggingface-cli repo create $HUGGINGFACE_USERNAME/$HUGGINGFACE_SPACE --type=space --sdk=streamlit

# Step 5: Clone Space and push files
git clone https://huggingface.co/spaces/$HUGGINGFACE_USERNAME/$HUGGINGFACE_SPACE
cd $HUGGINGFACE_SPACE

cp -r ../app/ui/streamlit_app.py ./
cp ../requirements.txt ./
git add .
git commit -m "Deploy PGOP demo to HF Spaces"
git push

echo "Deployment complete!"
echo "Visit your app at: https://huggingface.co/spaces/$HUGGINGFACE_USERNAME/$HUGGINGFACE_SPACE"
