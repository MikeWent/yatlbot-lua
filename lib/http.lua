local urlencode = require "urlencode"
local https = require "ssl.https"
local ltn12 = require "ltn12"

local _M = {}

function _M.request(method, url, params, custom_headers)
    -- combine request params into single string
    local req_params = ""
    if params then
        for i, v in pairs(params) do
            req_params = req_params .. i .. "=" .. urlencode.encode_url(v) .. "&"
        end
    end

    -- set default request headers
    local request_headers = {
        ["Content-Length"] = #req_params;
        ["Accept"] = "*/*";
        ["Connection"] = "Keep-Alive";
    }

    -- merge request headers with custom headers
    if custom_headers then
        for k,v in pairs(custom_headers) do request_headers[k] = v end
    end
    
    if method == "POST" then
        request_headers["Content-Type"] = "application/x-www-form-urlencoded";
    end

    -- make HTTP(S) request
    local response_body = {}
    local _, code = https.request {
        method = method,
        source = ltn12.source.string(req_params),
        url = url,
        headers = request_headers,
        sink = ltn12.sink.table(response_body)
    }

    local response = table.concat(response_body)
    return response, code
end

function _M.get(url, params, headers)
    return _M.request("GET", url, params, headers)
end

function _M.post(url, params, headers)
    return _M.request("POST", url, params, headers)
end

return _M