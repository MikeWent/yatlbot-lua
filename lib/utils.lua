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

return _M
