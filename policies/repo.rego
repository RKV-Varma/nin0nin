package repo

# Rule 1: Repo must have README.md
deny[msg] {
  not input.files("README.md")
  msg := "README.md file missing"
}

# Rule 2: Repo name must start with org prefix
deny[msg] {
  not startswith(input.name, "staging-")
  msg := sprintf("Repo name '%s' must start with 'staging-'", [input.name])
}

# Rule 3: Must contain a GitHub workflow
deny[msg] {
  not some f
  f := input.files[_]
  startswith(f, ".github/workflows")
  msg := "Missing GitHub Actions workflows"
}

# -------- Helper function --------
file_exists(filename) {
  some f
  f := input.files[_]
  f == filename
}
