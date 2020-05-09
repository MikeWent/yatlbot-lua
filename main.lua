#!/bin/lua

local tg = require 'lib.telegram'
local utils = require 'lib.utils'

local token = utils.lines_from("token.txt")[1]

if token == nil then
    print("Please specify bot token in token.txt")
    os.exit(1)
end

Bot = tg:init(token)
utils.inspect_json(Bot:request("getMe"))

Bot:add_handler(
    "message",
    function(event)
        return event.message.text == "/start"
    end,
    function(event)
        Bot:request("sendMessage", {chat_id = event.message.chat.id, text = "Hello world"})
    end
)

Bot:add_handler(
    "message",
    function(event)
        return event.message.text == "/ping"
    end,
    function(event)
        Bot:request("sendMessage", {chat_id = event.message.chat.id, text = "Pong, dear "..event.message.from.first_name})
    end
)

Bot:start_polling()
