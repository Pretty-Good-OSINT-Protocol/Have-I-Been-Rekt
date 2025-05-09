#!/bin/bash
cd ~/projects/hibr/Have-I-Been-Rekt || exit 1

# Create legacy folder if needed
mkdir -p legacy

# List of files to move
FILES=(
  "overview.md"
  "index.md"
  "architecture.md"
  "pgop_repo_structure.txt"
  "deploy_pgop_to_github_and_huggingface.sh"
  "test_osint_core.py"
  "test_plugin_loader.py"
)

echo "Moving legacy files..."
for FILE in "${FILES[@]}"; do
  if [ -f "$FILE" ]; then
    mv "$FILE" legacy/
    echo "Moved $FILE → legacy/"
  else
    echo "Skipped $FILE (not found)"
  fi
done

# Commit the changes
git add legacy/
git commit -m "Archive outdated files to legacy/"
git push origin main
