# TerraGuard for Neovim

Diagnostics and quick fixes from `terraguard lsp` (Neovim 0.10 or later).

With lazy.nvim:

```lua
{ "Karthik-099/TERRAGUARD", config = function(p)
    vim.opt.rtp:append(p.dir .. "/editors/nvim")
    require("terraguard").setup()
  end }
```

Or copy `lua/terraguard` into your config. Options: `cmd` (default
`{ "terraguard", "lsp" }`) and `filetypes`.
