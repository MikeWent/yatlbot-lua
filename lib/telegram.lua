local cqueues = require 'cqueues'
local json = require "cjson"
local http = require 'lib.http'
-- local utils = require "lib.utils"

local _M = {}
_M.__index = _M

function _M:init(token)
    local bot = setmetatable({}, _M)
    bot.token = token
    bot.handlers = {}
    bot.last_processed_update = 0
    return bot
end

function _M:request(method, params)
    -- https://core.telegram.org/bots/api#available-methods
    local req = http.request("https://api.telegram.org/bot"..self.token.."/"..method)
    req.headers:upsert(":method", 'POST')
    req.headers:upsert("content-type", "application/x-www-form-urlencoded") -- headers
    req:set_body(http.util.dict_to_query(params or {}))
    local h,stream = req:go()
    local r,err    = stream:get_body_as_string()
    local response = json.decode(r)
    assert(response.ok, 'Telegram API error #'..(response.error_code or '-1')..': '..(response.description or ''))
    return response.result
end

function _M:add_handler(event_type, filter_function, handler_function)
    -- https://core.telegram.org/bots/api#update

    --[[

        handlers = {
            "message" = {
                {filter1, handler1},
                {filter2, handler2},
                {filter3, handler3}
            },
            "callback_query" = {
                {filter10, handler10}
                {filter11, handler11}
            }
        }

        corresponding 'handler' executes ONLY if its 'filter' with 'event' argument returns true

    --]]
    if not self.handlers[event_type] then
        self.handlers[event_type] = {}
    end
    table.insert(self.handlers[event_type], {filter_function, handler_function})
end

function _M:handle_event(event)
    local event_id = event.update_id
    event.update_id = nil
    local event_type = next(event)
    -- local event_type = utils.table_keys(event)[1]
    local this_type_handlers = self.handlers[event_type]
    if #this_type_handlers > 0 then
        -- process each handler of this event type
        for n=1, #this_type_handlers do
            local filter = this_type_handlers[n][1]
            local handler = this_type_handlers[n][2]
            -- execute handler only if filter function succeed
            if filter(event) == true then
                handler(event)
            end
        end
    end

--    self.last_processed_update = event_id
end

function _M:start_polling()
    local dispatcher = cqueues.new()
    dispatcher:wrap(function()
        while true do
            local recent_updates = self:request("getUpdates", {timeout = 30, offset = self.last_processed_update + 1})
            self.last_processed_update = (#recent_updates>0) and recent_updates[#recent_updates].update_id or self.last_processed_update
            -- utils.inspect_json(recent_updates)
            for n = 1, #recent_updates do
                dispatcher:wrap(function() self:handle_event(recent_updates[n]) end)
            end
            cqueues.sleep(0.1)
        end
    end)
    dispatcher:loop()
end

return _M
