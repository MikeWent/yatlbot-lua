#!/bin/lua

local tg = require 'lib.telegram'
local utils = require 'lib.utils'

-- safely extract token from file, even if it does't exist
local token = utils.lines_from("token.txt")[1]

if token == {} then
    print("Please specify bot token in token.txt")
    os.exit(1)
end

Bot = tg:init(token)
utils.inspect_json(Bot:request("getMe"))
