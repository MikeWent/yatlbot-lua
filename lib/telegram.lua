local https = require "ssl.https"
local urlencode = require "urlencode"
local json = require "rapidjson"
local ltn12 = require "ltn12"

local _M = {}
_M.__index = _M

function _M:request(method, params)
    local req_params = ""
    if params then
        for i, v in pairs(params) do
            req_params = req_params .. i .. "=" .. urlencode.encode_url(v) .. "&"
        end
    end

    local response_body = {}
    local res, code = https.request {
		method = "POST",
        source = ltn12.source.string(req_params),
		url = "https://api.telegram.org/bot"..self.token.."/"..method,
		headers = {
	  		["Content-Type"] = "application/x-www-form-urlencoded";
  	  		["Content-Length"] = #req_params;
	  		["Accept"] = '*/*';
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

function _M:init(token)
    local bot = setmetatable({}, _M)
    bot.token = token
    return bot
end

return _M
