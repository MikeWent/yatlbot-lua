local inspect = require 'inspect'

local _M = {}

function _M.file_exists(file)
    local f = io.open(file, "rb")
    if f then f:close() end
    return f ~= nil
end
  
function _M.lines_from(file)
    if not _M.file_exists(file) then return {} end
    local lines = {}
    for line in io.lines(file) do
        lines[#lines + 1] = line
    end
    return lines
end

function _M.inspect_json(json)
    local function remove_all_metatables(item, path)
        if path[#path] ~= inspect.METATABLE then return item end
    end
    print(inspect(json, {process = remove_all_metatables}))
end

function _M.table_keys(t)
    -- https://stackoverflow.com/questions/12674345/lua-retrieve-list-of-keys-in-a-table#12674376
    local keyset = {}
    local n = 0

    for k, _ in pairs(t) do
      n = n + 1
      keyset[n] = k
    end
    
    table.sort(keyset)
    return keyset
end

return _M
