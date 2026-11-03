# TerraGuard for JetBrains IDEs

IntelliJ IDEA, GoLand, PyCharm and the other JetBrains IDEs run `terraguard lsp`
through the free LSP4IJ plugin.

1. Install `terraguard` and put it on PATH.
2. Install **LSP4IJ** from the JetBrains Marketplace.
3. Settings > Languages & Frameworks > Language Servers > `+`.
   Name: `TerraGuard`. Command: `terraguard lsp`.
4. Mappings > File name patterns: `*.tf`, `*.tfvars`, `*.tofu`, `*.yaml`, `*.yml`,
   `*.json`, `Dockerfile`.

Findings appear as inspections and safe fixes as quick fixes (Alt+Enter).
