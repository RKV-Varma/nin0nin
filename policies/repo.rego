package repo

# Rule 1: Repo must have README.md
deny[msg] {
  not input.files[_] == "README.md"
  msg := "README.md file missing"
}

# Rule 2: Repo name must start with org prefix
deny[msg] {
  not startswith(input.name, "staging-")
  msg := sprintf("Repo name '%s' must start with 'staging-'", [input.name])
}

# Rule 3: Must contain a GitHub workflow
deny[msg] {
  not input.files[_] == ".github/workflows"
  msg := "Missing GitHub Actions workflows"
}
