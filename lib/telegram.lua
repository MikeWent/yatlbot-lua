local https = require "ssl.https"
local urlencode = require "urlencode"
local json = require "rapidjson"
local ltn12 = require "ltn12"

local utils = require "lib.utils"

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
    local req_params = ""
    if params then
        for i, v in pairs(params) do
            req_params = req_params .. i .. "=" .. urlencode.encode_url(v) .. "&"
        end
    end

    local url = "https://api.telegram.org/bot"..self.token.."/"..method
    local response_body = {}
    local res, code = https.request {
        method = "POST",
        source = ltn12.source.string(req_params),
        url = url,
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded";
            ["Content-Length"] = #req_params;
            ["Accept"] = "*/*";
            ["Connection"] = "Keep-Alive";
        },
        sink = ltn12.sink.table(response_body)
    }

    local response = json.decode(table.concat(response_body))

    if response["ok"] then
        return response["result"]
    else
        error("Telegram API error #"..response["error_code"]..": "..response["description"])
    end
end

function _M:add_handler(event_type, filter, callback_function)
    -- https://core.telegram.org/bots/api#update
    if not self.handlers[event_type] then
        self.handlers[event_type] = {}
    end
    table.insert(self.handlers[event_type], {filter, callback_function})
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

    self.last_processed_update = event_id
end

function _M:start_polling()
    while true do
        local recent_updates = self:request("getUpdates", {timeout = 30, offset = self.last_processed_update + 1})
        -- utils.inspect_json(recent_updates)
        for n = 1, #recent_updates do
            self:handle_event(recent_updates[n])
        end
    end
end

return _M
