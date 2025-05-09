#!/bin/bash
REPO="Pretty-Good-OSINT-Protocol/Have-I-Been-Rekt"

# Create labels
echo "Creating labels..."
gh label create "dev-task" --color FF5733 --description "Tasks assigned to hired developer"
gh label create "vibe-code" --color 33FFCE --description "Tasks for Ben to vibe code"
gh label create "high-priority" --color FF3333 --description "Must-do for MVP launch"
gh label create "estimate:1h" --color 3399FF --description "Estimated 1 hour task"
gh label create "estimate:2h" --color 3377FF --description "Estimated 2 hour task"
gh label create "estimate:3h" --color 3355FF --description "Estimated 3 hour task"
gh label create "estimate:4h" --color 3333FF --description "Estimated 4 hour task"
#!/bin/bash
REPO="Pretty-Good-OSINT-Protocol/Have-I-Been-Rekt"

# Create labels (safe to rerun)
gh label create "dev-task" --color FF5733 --description "Tasks assigned to hired developer" || true
gh label create "vibe-code" --color 33FFCE --description "Tasks for Ben to vibe code" || true
gh label create "high-priority" --color FF3333 --description "Must-do for MVP launch" || true
gh label create "estimate:1h" --color 3399FF --description "Estimated 1 hour task" || true
gh label create "estimate:2h" --color 3377FF --description "Estimated 2 hour task" || true
gh label create "estimate:3h" --color 3355FF --description "Estimated 3 hour task" || true
gh label create "estimate:4h" --color 3333FF --description "Estimated 4 hour task" || true

# Update existing issues with individual label flags
gh issue edit 7 --repo "$REPO" --add-label "dev-task" --add-label "estimate:3h" --add-label "high-priority"
gh issue edit 8 --repo "$REPO" --add-label "dev-task" --add-label "estimate:2h"
gh issue edit 9 --repo "$REPO" --add-label "dev-task" --add-label "estimate:4h" --add-label "high-priority"
gh issue edit 10 --repo "$REPO" --add-label "vibe-code" --add-label "estimate:2h"
gh issue edit 11 --repo "$REPO" --add-label "vibe-code" --add-label "estimate:1h"
gh issue edit 12 --repo "$REPO" --add-label "vibe-code" --add-label "estimate:1h"

# Create new issues (no change needed—labels already comma-free)
gh issue create --repo "$REPO" --title "Implement cost estimation UX" --body "- [ ] Estimate API/AI costs\n- [ ] Show to user before submit" --label "dev-task,estimate:2h,high-priority"
gh issue create --repo "$REPO" --title "Free vs Paid tier logic" --body "- [ ] Gate OSINT behind payments\n- [ ] Allow dev override" --label "dev-task,estimate:2h"
gh issue create --repo "$REPO" --title "Termux/CLI user script" --body "- [ ] Make basic local version for testing\n- [ ] Include redaction" --label "vibe-code,estimate:2h"
gh issue create --repo "$REPO" --title "AI prompt design for wallet summary" --body "- [ ] Create YAML or JSON format\n- [ ] Test in Ollama" --label "vibe-code,estimate:1h"
gh issue create --repo "$REPO" --title "CanHost deployment guide" --body "- [ ] Instructions for Canadian hosting\n- [ ] Docker setup if possible" --label "dev-task,estimate:2h"

echo "✅ All issues updated and labeled!"gh issue edit 8 --repo "$REPO" --add-label "dev-task" --add-label "estimate:2h"
# Update existing issues
echo "Updating existing issues..."
gh issue edit 7 --repo "$REPO" --add-label "dev-task,estimate:3h,high-priority"
gh issue edit 8 --repo "$REPO" --add-label
#!/bin/bash
REPO="Pretty-Good-OSINT-Protocol/Have-I-Been-Rekt"

# Create labels (safe to rerun)
gh label create "dev-task" --color FF5733 --description "Tasks assigned to hired developer" || true
gh label create "vibe-code" --color 33FFCE --description "Tasks for Ben to vibe code" || true
gh label create "high-priority" --color FF3333 --description "Must-do for MVP launch" || true
gh label create "estimate:1h" --color 3399FF --description "Estimated 1 hour task" || true
gh label create "estimate:2h" --color 3377FF --description "Estimated 2 hour task" || true
gh label create "estimate:3h" --color 3355FF --description "Estimated 3 hour task" || true
gh label create "estimate:4h" --color 3333FF --description "Estimated 4 hour task" || true

# Update existing issues with individual label flags
gh issue edit 7 --repo "$REPO" --add-label "dev-task" --add-label "estimate:3h" --add-label "high-priority"
gh issue edit 8 --repo "$REPO" --add-label "dev-task" --add-label "estimate:2h"
gh issue edit 9 --repo "$REPO" --add-label "dev-task" --add-label "estimate:4h" --add-label "high-priority"
gh issue edit 10 --repo "$REPO" --add-label "vibe-code" --add-label "estimate:2h"
gh issue edit 11 --repo "$REPO" --add-label "vibe-code" --add-label "estimate:1h"
gh issue edit 12 --repo "$REPO" --add-label "vibe-code" --add-label "estimate:1h"

# Create new issues (no change needed—labels already comma-free)
gh issue create --repo "$REPO" --title "Implement cost estimation UX" --body "- [ ] Estimate API/AI costs\n- [ ] Show to user before submit" --label "dev-task,estimate:2h,high-priority"
gh issue create --repo "$REPO" --title "Free vs Paid tier logic" --body "- [ ] Gate OSINT behind payments\n- [ ] Allow dev override" --label "dev-task,estimate:2h"
gh issue create --repo "$REPO" --title "Termux/CLI user script" --body "- [ ] Make basic local version for testing\n- [ ] Include redaction" --label "vibe-code,estimate:2h"
gh issue create --repo "$REPO" --title "AI prompt design for wallet summary" --body "- [ ] Create YAML or JSON format\n- [ ] Test in Ollama" --label "vibe-code,estimate:1h"
gh issue create --repo "$REPO" --title "CanHost deployment guide" --body "- [ ] Instructions for Canadian hosting\n- [ ] Docker setup if possible" --label "dev-task,estimate:2h"

echo "✅ All issues updated and labeled!"
