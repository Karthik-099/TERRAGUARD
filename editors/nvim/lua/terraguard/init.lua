-- TerraGuard for Neovim: starts `terraguard lsp` for infrastructure files.
-- require("terraguard").setup({ cmd = { "terraguard", "lsp" } })
local M = {}

M.filetypes = { "terraform", "terraform-vars", "hcl", "yaml", "json", "dockerfile" }

function M.setup(opts)
  opts = opts or {}
  local cmd = opts.cmd or { "terraguard", "lsp" }
  if vim.fn.executable(cmd[1]) ~= 1 then
    vim.notify("terraguard: " .. cmd[1] .. " not found on PATH", vim.log.levels.WARN)
    return
  end
  vim.api.nvim_create_autocmd("FileType", {
    pattern = opts.filetypes or M.filetypes,
    callback = function(args)
      local root = vim.fs.root(args.buf, { ".terraguard.yml", ".git" }) or vim.fn.getcwd()
      vim.lsp.start({ name = "terraguard", cmd = cmd, root_dir = root }, { bufnr = args.buf })
    end,
  })
end

return M
