-- Called only with constant action names, while the upstream API swap lock is held.
local M = {}
function M.run(action)
	return os.execute("python3 /opt/bw-lkg/guard.py " .. action) == 0
end
return M
