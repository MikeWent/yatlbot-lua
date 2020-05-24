local cqueues = require "cqueues"
local cc = require "cqueues.condition"
local ce = require "cqueues.errno"
local ca = require "cqueues.auxlib"
local cs = require "cqueues.socket"
local openssl = require 'openssl'
openssl.ssl = require 'openssl.ssl'
openssl.ssl.context = require 'openssl.ssl.context'
openssl.pkey = require 'openssl.pkey'
openssl.x509 = require 'openssl.x509'
openssl.x509.verify_param = require 'openssl.x509.verify_param'
openssl.bignum = require 'openssl.bignum'
openssl.rand = require 'openssl.rand'
openssl.x509.name = require 'openssl.x509.name'
openssl.x509.altname = require 'openssl.x509.altname'

-- HTTP status list
-- This list should be kept in sync with IANA.
local HTTP_STATUS = setmetatable({
    ["100"] = "Continue";
    ["101"] = "Switching Protocols";
    ["102"] = "Processing";
    ["103"] = "Early Hints";

    ["200"] = "OK";
    ["201"] = "Created";
    ["202"] = "Accepted";
    ["203"] = "Non-Authoritative Information";
    ["204"] = "No Content";
    ["205"] = "Reset Content";
    ["206"] = "Partial Content";
    ["207"] = "Multi-Status";
    ["208"] = "Already Reported";

    ["226"] = "IM Used";

    ["300"] = "Multiple Choices";
    ["301"] = "Moved Permanently";
    ["302"] = "Found";
    ["303"] = "See Other";
    ["304"] = "Not Modified";
    ["305"] = "Use Proxy";

    ["307"] = "Temporary Redirect";
    ["308"] = "Permanent Redirect";

    ["400"] = "Bad Request";
    ["401"] = "Unauthorized";
    ["402"] = "Payment Required";
    ["403"] = "Forbidden";
    ["404"] = "Not Found";
    ["405"] = "Method Not Allowed";
    ["406"] = "Not Acceptable";
    ["407"] = "Proxy Authentication Required";
    ["408"] = "Request Timeout";
    ["409"] = "Conflict";
    ["410"] = "Gone";
    ["411"] = "Length Required";
    ["412"] = "Precondition Failed";
    ["413"] = "Request Entity Too Large";
    ["414"] = "Request-URI Too Long";
    ["415"] = "Unsupported Media Type";
    ["416"] = "Requested Range Not Satisfiable";
    ["417"] = "Expectation Failed";
    ["418"] = "I'm a teapot"; -- not in IANA registry

    ["421"] = "Misdirected Request";
    ["422"] = "Unprocessable Entity";
    ["423"] = "Locked";
    ["424"] = "Failed Dependency";

    ["426"] = "Upgrade Required";

    ["428"] = "Precondition Required";
    ["429"] = "Too Many Requests";

    ["431"] = "Request Header Fields Too Large";

    ["451"] = "Unavailable For Legal Reasons";

    ["500"] = "Internal Server Error";
    ["501"] = "Not Implemented";
    ["502"] = "Bad Gateway";
    ["503"] = "Service Unavailable";
    ["504"] = "Gateway Timeout";
    ["505"] = "HTTP Version Not Supported";
    ["506"] = "Variant Also Negotiates";
    ["507"] = "Insufficient Storage";
    ["508"] = "Loop Detected";

    ["510"] = "Not Extended";
    ["511"] = "Network Authentication Required";
}, {__index = function() return "Unassigned" end})

-- HTTP headers data structure/type
local headers_new
do
    local headers_entry_methods = {}
    local headers_entry_mt = {
        __name = "http.headers.entry";
        __index = headers_entry_methods;
    }

    local never_index_defaults = {
        authorization = true;
        ["proxy-authorization"] = true;
        cookie = true;
        ["set-cookie"] = true;
    }

    local function new_entry(name, value, never_index)
        if never_index == nil then
            never_index = never_index_defaults[name] or false
        end
        return setmetatable({
            name = name;
            value = value;
            never_index = never_index;
        }, headers_entry_mt)
    end

    function headers_entry_methods:modify(value, never_index)
        self.value = value
        if never_index == nil then
            never_index = never_index_defaults[self.name] or false
        end
        self.never_index = never_index
    end

    function headers_entry_methods:unpack()
        return self.name, self.value, self.never_index
    end

    function headers_entry_methods:clone()
        return new_entry(self.name, self.value, self.never_index)
    end

    local headers_methods = {}
    local headers_mt = {
        __name = "http.headers";
        __index = headers_methods;
    }

    function headers_methods:len()
        return self._n
    end
    headers_mt.__len = headers_methods.len

    function headers_mt:__tostring()
        return string.format("http.headers{%d headers}", self._n)
    end

    local function add_to_index(_index, name, i)
        local dex = _index[name]
        if dex == nil then
            dex = {n=1, i}
            _index[name] = dex
        else
            local n = dex.n + 1
            dex[n] = i
            dex.n = n
        end
    end

    local function rebuild_index(self)
        local index = {}
        for i=1, self._n do
            local entry = self._data[i]
            add_to_index(index, entry.name, i)
        end
        self._index = index
    end

    function headers_methods:clone()
        local index, new_data = {}, {}
        for i=1, self._n do
            local entry = self._data[i]
            new_data[i] = entry:clone()
            add_to_index(index, entry.name, i)
        end
        return setmetatable({
            _n = self._n;
            _data = new_data;
            _index = index;
        }, headers_mt)
    end

    function headers_methods:append(name, ...)
        local n = self._n + 1
        self._data[n] = new_entry(name, ...)
        add_to_index(self._index, name, n)
        self._n = n
    end

    function headers_methods:each()
        local i = 0
        return function(self) -- luacheck: ignore 432
            if i >= self._n then return end
            i = i + 1
            local entry = self._data[i]
            return entry:unpack()
        end, self
    end
    headers_mt.__pairs = headers_methods.each

    function headers_methods:has(name)
        local dex = self._index[name]
        return dex ~= nil
    end

    function headers_methods:delete(name)
        local dex = self._index[name]
        if dex then
            local n = dex.n
            for i=n, 1, -1 do
                table.remove(self._data, dex[i])
            end
            self._n = self._n - n
            rebuild_index(self)
            return true
        else
            return false
        end
    end

    function headers_methods:geti(i)
        local e = self._data[i]
        if e == nil then return nil end
        return e:unpack()
    end

    function headers_methods:get_as_sequence(name)
        local dex = self._index[name]
        if dex == nil then return { n = 0; } end
        local r = { n = dex.n; }
        for i=1, r.n do
            r[i] = self._data[dex[i]].value
        end
        return r
    end

    function headers_methods:get(name)
        local r = self:get_as_sequence(name)
        return unpack(r, 1, r.n)
    end

    function headers_methods:get_comma_separated(name)
        local r = self:get_as_sequence(name)
        if r.n == 0 then
            return nil
        else
            return table.concat(r, ",", 1, r.n)
        end
    end

    function headers_methods:modifyi(i, ...)
        local e = self._data[i]
        if e == nil then error("invalid index") end
        e:modify(...)
    end

    function headers_methods:upsert(name, ...)
        local dex = self._index[name]
        if dex == nil then
            self:append(name, ...)
        else
            assert(dex[2] == nil, "Cannot upsert multi-valued field")
            self:modifyi(dex[1], ...)
        end
    end

    local function default_cmp(a, b)
        if a.name ~= b.name then
            -- Things with a colon *must* be before others
            local a_is_colon = a.name:sub(1,1) == ":"
            local b_is_colon = b.name:sub(1,1) == ":"
            if a_is_colon and not b_is_colon then
                return true
            elseif not a_is_colon and b_is_colon then
                return false
            else
                return a.name < b.name
            end
        end
        if a.value ~= b.value then
            return a.value < b.value
        end
        return a.never_index
    end

    function headers_methods:sort()
        table.sort(self._data, default_cmp)
        rebuild_index(self)
    end

    function headers_methods:dump(file, prefix)
        file = file or io.stderr
        prefix = prefix or ""
        for name, value in self:each() do
            assert(file:write(string.format("%s%s: %s\n", prefix, name, value)))
        end
        assert(file:flush())
    end
    
    function headers_new()
        return setmetatable({
            _n = 0;
            _data = {};
            _index = {};
        }, headers_mt)
    end
end

-- FIFO module
local fifo = {}
do
    local fifo_mt = {
        __index = fifo ;
        __newindex = function() error("Tried to set table field in fifo") end ;
    }
    local function is_integer(x) return x % 1 == 0 end
    local function empty_default(_) error ( "Fifo empty" ) end

    function fifo:length ( )
        return self.tail - self.head + 1
    end
    fifo_mt.__len = fifo.length

    -- Peek at the nth item
    function fifo:peek ( n )
        n = n or 1
        assert(is_integer(n), "bad index to :peek()")

        local index = self.head - 1 + n
        if index > self.tail then
            return nil, false
        else
            return self.data[index], true
        end
    end

    function fifo:push (v)
        self.tail = self.tail + 1
        self.data[self.tail] = v
    end

    function fifo:pop ()
        local head , tail = self.head , self.tail
        if head > tail then return self:empty() end
        local v = self.data[head]
        self.data[head] = nil
        self.head = head + 1
        return v
    end

    function fifo:insert (n, v)
        local head , tail = self.head , self.tail

        if n <= 0 or head + n > tail + 2 or not is_integer(n) then
            error("bad index to :insert()")
        end

        local p = head + n - 1
        if p <= (head + tail)/2 then
            for i = head , p do
                self.data[i- 1] = self.data[i]
            end
            self.data[p- 1] = v
            self.head = head - 1
        else
            for i = tail , p , -1 do
                self.data[i+ 1] = self.data[i]
            end
            self.data[p] = v
            self.tail = tail + 1
        end
    end

    function fifo:remove ( n )
        local head , tail = self.head , self.tail

        if n <= 0 or not is_integer(n) then
            error("bad index to :remove()")
        end

        if head + n - 1 > tail then return self:empty() end

        local p = head + n - 1
        local v = self.data[p]

        if p <= (head + tail)/2 then
            for i = p , head , -1 do
                self.data[i] = self.data[i-1]
            end
            self.head = head + 1
        else
            for i = p , tail do
                self.data[i] = self.data[i+1]
            end
            self.tail = tail - 1
        end

        return v
    end

    function fifo:setempty ( func )
        self.empty = func
        return self
    end

    function fifo.new ( ... )
        return setmetatable({
            empty = empty_default;
            head = 1;
            tail = select("#",...);
            data = {...};
        }, fifo_mt)
    end
end

-- This module implements the socket level streams
local stream = {}
do
    local CHUNK_SIZE = 2^20 -- write in 1MB chunks

    function stream:checktls()
        return self.connection:checktls()
    end

    function stream:localname()
        return self.connection:localname()
    end

    function stream:peername()
        return self.connection:peername()
    end

    -- 100-Continue response
    local continue_headers = headers_new()
    continue_headers:append(":status", "100")
    function stream:write_continue(timeout)
        return self:write_headers(continue_headers, false, timeout)
    end

    -- need helper to discard 'last' argument
    -- (which would otherwise end up going in 'timeout')
    local function each_chunk_helper(self)
        return self:get_next_chunk()
    end
    function stream:each_chunk()
        return each_chunk_helper, self
    end

    function stream:get_body_as_string(timeout)
        local deadline = timeout and (cqueues.monotime()+timeout)
        local body, i = {}, 0
        while true do
            local chunk, err, errno = self:get_next_chunk(timeout)
            if chunk == nil then
                if err == nil then
                    break
                else
                    return nil, err, errno
                end
            end
            i = i + 1
            body[i] = chunk
            timeout = deadline and (deadline-cqueues.monotime())
        end
        return table.concat(body, "", 1, i)
    end

    function stream:get_body_chars(n, timeout)
        local deadline = timeout and (cqueues.monotime()+timeout)
        local body, i, len = {}, 0, 0
        while len < n do
            local chunk, err, errno = self:get_next_chunk(timeout)
            if chunk == nil then
                if err == nil then
                    break
                else
                    return nil, err, errno
                end
            end
            i = i + 1
            body[i] = chunk
            len = len + #chunk
            timeout = deadline and (deadline-cqueues.monotime())
        end
        if i == 0 then
            return nil
        end
        local r = table.concat(body, "", 1, i)
        if n < len then
            self:unget(r:sub(n+1, -1))
            r = r:sub(1, n)
        end
        return r
    end

    function stream:get_body_until(pattern, plain, include_pattern, timeout)
        local deadline = timeout and (cqueues.monotime()+timeout)
        local body
        while true do
            local chunk, err, errno = self:get_next_chunk(timeout)
            if chunk == nil then
                if err == nil then
                    return body, err
                else
                    return nil, err, errno
                end
            end
            if body then
                body = body .. chunk
            else
                body = chunk
            end
            local s, e = body:find(pattern, 1, plain)
            if s then
                if e < #body then
                    self:unget(body:sub(e+1, -1))
                end
                if include_pattern then
                    return body:sub(1, e)
                else
                    return body:sub(1, s-1)
                end
            end
            timeout = deadline and (deadline-cqueues.monotime())
        end
    end

    function stream:save_body_to_file(file, timeout)
        local deadline = timeout and (cqueues.monotime()+timeout)
        while true do
            local chunk, err, errno = self:get_next_chunk(timeout)
            if chunk == nil then
                if err == nil then
                    break
                else
                    return nil, err, errno
                end
            end
            assert(file:write(chunk))
            timeout = deadline and (deadline-cqueues.monotime())
        end
        return true
    end

    function stream:get_body_as_file(timeout)
        local file = assert(io.tmpfile())
        local ok, err, errno = self:save_body_to_file(file, timeout)
        if not ok then
            return nil, err, errno
        end
        assert(file:seek("set"))
        return file
    end

    function stream:write_body_from_string(str, timeout)
        return self:write_chunk(str, true, timeout)
    end

    function stream:write_body_from_file(options, timeout)
        local deadline = timeout and (cqueues.monotime()+timeout)
        local file, count
        if io.type(options) then -- lua-http <= 0.2 took a file handle
            file = options
        else
            file = options.file
            count = options.count
        end
        if count == nil then
            count = math.huge
        elseif type(count) ~= "number" or count < 0 or count % 1 ~= 0 then
            error("invalid .count parameter (expected positive integer)")
        end
        while count > 0 do
            local chunk, err = file:read(math.min(CHUNK_SIZE, count))
            if chunk == nil then
                if err then
                    error(err)
                elseif count ~= math.huge and count > 0 then
                    error("unexpected EOF")
                end
                break
            end
            local ok, err2, errno2 = self:write_chunk(chunk, false, deadline and (deadline-cqueues.monotime()))
            if not ok then
                return nil, err2, errno2
            end
            count = count - #chunk
        end
        return self:write_chunk("", true, deadline and (deadline-cqueues.monotime()))
    end

    local stream_mt = {
        __name = "http.stream";
        __index = stream;
    }
--    stream_mt.__tostring = function() return string.format("http.stream{connection=%s;state=%q}", tostring(self.connection), self.state) end;
    stream.max_header_lines = 100;
    stream.clean_shutdown_limit = 500*1024;
    stream.valid_states = {
        ["idle"] = 1; -- initial
        ["open"] = 2; -- have sent or received headers; haven't sent body yet
        ["half closed (local)"] = 3; -- have sent whole body
        ["half closed (remote)"] = 3; -- have received whole body
        ["closed"] = 4; -- complete
    }
    function stream:set_state(new)
        local new_order = assert(stream.valid_states[new])
        local old = self.state
        if new_order <= stream.valid_states[old] then
            error("invalid state progression ('"..old.."' to '"..new.."')")
        end
        local have_lock, want_no_lock
        local blocking_pipeline, notify_pipeline
        if self.type == "server" then
            -- If we have just finished reading the request then remove our read lock
            have_lock = old == "idle" or old == "open" or old == "half closed (local)"
            want_no_lock = new == "half closed (remote)" or new == "closed"
            -- If we have just finished writing the response
            blocking_pipeline = old == "idle" or old == "open" or old == "half closed (remote)"
            notify_pipeline = blocking_pipeline and (new == "half closed (local)" or new == "closed")
        else -- client
            -- If we have just finished writing the request then remove our write lock
            have_lock = old == "open" or old == "half closed (remote)"
            want_no_lock = new == "half closed (local)" or new == "closed"
            -- If we have just finished reading the response;
            blocking_pipeline = old == "idle" or old == "open" or old == "half closed (local)"
            notify_pipeline = blocking_pipeline and (new == "half closed (remote)" or new == "closed")
        end
        self.state = new
        if have_lock then
            assert(self.connection.req_locked == self)
            if want_no_lock then
                self.connection.req_locked = nil
                self.connection.req_cond:signal(1)
            end
        end
        local pipeline_empty
        if notify_pipeline then
            assert(self.connection.pipeline:pop() == self)
            local next_stream = self.connection.pipeline:peek()
            if next_stream then
                pipeline_empty = false
                next_stream.pipeline_cond:signal()
            else
                pipeline_empty = true
            end
        else
            pipeline_empty = not blocking_pipeline
        end
        if self.close_when_done then
            if new == "half closed (remote)" then
                self.connection:shutdown("r")
            elseif new == "half closed (local)" and self.type == "server" then
                -- NOTE: Do not shutdown("w") the socket when a client moves to
                -- "half closed (local)", many servers will close a connection
                -- immediately if a client closes their write stream
                self.connection:shutdown("w")
            elseif new == "closed" then
                self.connection:shutdown()
            end
        end
        if want_no_lock and pipeline_empty then
            self.connection:onidle()(self.connection)
        end
    end

    local bad_request_headers = headers_new()
    bad_request_headers:append(":status", "400")
    local server_error_headers = headers_new()
    server_error_headers:append(":status", "503")
    function stream:shutdown()
        if self.state == "idle" then
            self:set_state("closed")
        else
            if self.type == "server" and (self.state == "open" or self.state == "half closed (remote)") then
                -- Make sure we're at the front of the pipeline
                if self.connection.pipeline:peek() ~= self then
                    -- FIXME: shouldn't have time-taking operation here
                    self.pipeline_cond:wait() -- wait without a timeout should never fail
                    assert(self.connection.pipeline:peek() == self)
                end
                if not self.body_write_type then
                    -- Can send an automatic error response
                    local error_headers
                    if self.connection:error("r") == ce.EILSEQ then
                        error_headers = bad_request_headers
                    else
                        error_headers = server_error_headers
                    end
                    self:write_headers(error_headers, true, 0)
                end
            end
            -- read any remaining available response and get out of the way
            local start = self.stats_recv
            while (self.state == "open" or self.state == "half closed (local)") and (self.stats_recv - start) < self.clean_shutdown_limit do
                if not self:step(0) then
                    break
                end
            end

            if self.state ~= "closed" then
                -- This is a bad situation: we are trying to shutdown a connection that has the body partially sent
                -- Especially in the case of Connection: close, where closing indicates EOF,
                -- this will result in a client only getting a partial response.
                -- Could also end up here if a client sending headers fails.
                if self.connection.socket then
                    self.connection.socket:shutdown()
                end
                self:set_state("closed")
            end
        end
        return true
    end

    function stream:step(timeout)
        if self.state == "open" or self.state == "half closed (local)" or (self.state == "idle" and self.type == "server") then
            if self.connection.socket == nil then
                return nil, ce.strerror(ce.EPIPE), ce.EPIPE
            end
            if not self.has_main_headers then
                local headers, err, errno = self:read_headers(timeout)
                if headers == nil then
                    return nil, err, errno
                end
                self.headers_fifo:push(headers)
                self.headers_cond:signal(1)
                return true
            end
            if self.body_read_left ~= 0 then
                local chunk, err, errno = self:read_next_chunk(timeout)
                if chunk == nil then
                    if err == nil then
                        return true
                    end
                    return nil, err, errno
                end
                self.chunk_fifo:push(chunk)
                self.chunk_cond:signal()
                return true
            end
            if self.body_read_type == "chunked" then
                local trailers, err, errno = self:read_headers(timeout)
                if trailers == nil then
                    return nil, err, errno
                end
                self.headers_fifo:push(trailers)
                self.headers_cond:signal(1)
                return true
            end
        end
        if self.state == "half closed (remote)" then
            return nil, ce.strerror(ce.EIO), ce.EIO
        end
        return true
    end

    -- read_headers may be called more than once for a stream
    -- e.g. for 100 Continue
    -- this function *should never throw* under normal operation
    function stream:read_headers(timeout)
        local deadline = timeout and (cqueues.monotime()+timeout)
        if self.state == "closed" or self.state == "half closed (remote)" then
            return nil
        end
        local status_code
        local is_trailers = self.body_read_type == "chunked"
        local headers = self.headers_in_progress
        if not headers then
            if is_trailers then
                headers = headers_new()
            elseif self.type == "server" then
                if self.state == "half closed (local)" then
                    return nil
                end
                local method, path, httpversion = self.connection:read_request_line(0)
                if method == nil then
                    if httpversion == ce.ETIMEDOUT then
                        timeout = deadline and deadline-cqueues.monotime()
                        if cqueues.poll(self.connection.socket, timeout) ~= timeout then
                            return self:read_headers(deadline and deadline-cqueues.monotime())
                        end
                    end
                    return nil, path, httpversion
                end
                self.req_method = method
                self.peer_version = httpversion
                headers = headers_new()
                headers:append(":method", method)
                if method == "CONNECT" then
                    headers:append(":authority", path)
                else
                    headers:append(":path", path)
                end
                headers:append(":scheme", self:checktls() and "https:" or "http:")
                self:set_state("open")
            else -- client
                -- Make sure we're at front of connection pipeline
                if self.connection.pipeline:peek() ~= self then
                    assert(cqueues.running(), "cannot wait for condition if not within a cqueues coroutine")
                    if cqueues.poll(self.pipeline_cond, timeout) == timeout then
                        return nil, ce.strerror(ce.ETIMEDOUT), ce.ETIMEDOUT
                    end
                    assert(self.connection.pipeline:peek() == self)
                end
                local httpversion, reason_phrase
                httpversion, status_code, reason_phrase = self.connection:read_status_line(0)
                if httpversion == nil then
                    if reason_phrase == ce.ETIMEDOUT then
                        timeout = deadline and deadline-cqueues.monotime()
                        if cqueues.poll(self.connection.socket, timeout) ~= timeout then
                            return self:read_headers(deadline and deadline-cqueues.monotime())
                        end
                    elseif status_code == nil then
                        return nil, ce.strerror(ce.EPIPE), ce.EPIPE
                    end
                    return nil, status_code, reason_phrase
                end
                self.peer_version = httpversion
                headers = headers_new()
                headers:append(":status", status_code)
                -- reason phase intentionally does not exist in HTTP2; discard for consistency
            end
            self.headers_in_progress = headers
        else
            if not is_trailers and self.type == "client" then
                status_code = headers:get(":status")
            end
        end

        -- Use while loop for lua 5.1 compatibility
        while true do
            if headers:len() >= self.max_header_lines then
                return nil, ce.strerror(ce.E2BIG), ce.E2BIG
            end
            local k, v, errno = self.connection:read_header(0)
            if k == nil then
                if v ~= nil then
                    if errno == ce.ETIMEDOUT then
                        timeout = deadline and deadline-cqueues.monotime()
                        if cqueues.poll(self.connection.socket, timeout) ~= timeout then
                            return self:read_headers(deadline and deadline-cqueues.monotime())
                        end
                    end
                    return nil, v, errno
                end
                break -- Success: End of headers.
            end
            k = k:lower() -- normalise to lower case
            if k == "host" and not is_trailers then
                k = ":authority"
            end
            headers:append(k, v)
        end

        do
            local ok, err, errno = self.connection:read_headers_done(0)
            if ok == nil then
                if errno == ce.ETIMEDOUT then
                    timeout = deadline and deadline-cqueues.monotime()
                    if cqueues.poll(self.connection.socket, timeout) ~= timeout then
                        return self:read_headers(deadline and deadline-cqueues.monotime())
                    end
                elseif err == nil then
                    return nil, ce.strerror(ce.EPIPE), ce.EPIPE
                end
                return nil, err, errno
            end
            self.headers_in_progress = nil
            self.has_main_headers = status_code == nil or status_code:sub(1,1) ~= "1" or status_code == "101"
        end

        do -- if client is sends `Connection: close`, server knows it can close at end of response
            local h = headers:get("connection")
            if h == 'close' then self.close_when_done = true end
        end

        -- Now guess if there's a body...
        -- RFC 7230 Section 3.3.3
        local no_body
        if is_trailers then
            -- there cannot be a body after trailers
            no_body = true
        elseif self.type == "client" and (
            self.req_method == "HEAD"
            or status_code == "204"
            or status_code == "304"
        ) then
            no_body = true
        elseif self.type == "client" and (
            status_code:sub(1,1) == "1"
        ) then
            -- note: different to spec:
            -- we don't want to go into body reading mode;
            -- we want to stay in header modes
            no_body = false
            if status_code == "101" then
                self.body_read_type = "close"
            end
        elseif headers:has("transfer-encoding") then
            no_body = false
            local last_transfer_encoding = headers:get("transfer-encoding") 
            if last_transfer_encoding == "chunked" then
                self.body_read_type = "chunked"
            else
                self.body_read_type = "close"
            end
        elseif headers:has("content-length") then
            local cl = tonumber(headers:get("content-length"), 10)
            if cl == nil then
                return nil, "invalid content-length"
            end
            if cl == 0 then
                no_body = true
            else
                no_body = false
                self.body_read_type = "length"
                self.body_read_left = cl
            end
        elseif self.type == "server" then
            -- A request defaults to no body
            no_body = true
        else -- client
            no_body = false
            self.body_read_type = "close"
        end
        if no_body then
            if self.state == "open" then
                self:set_state("half closed (remote)")
            else -- self.state == "half closed (local)"
                self:set_state("closed")
            end
        end
        return headers
    end

    function stream:get_headers(timeout)
        if self.headers_fifo:length() > 0 then
            return self.headers_fifo:pop()
        else
            if self.state == "closed" or self.state == "half closed (remote)" then
                return nil
            end
            local deadline = timeout and cqueues.monotime()+timeout
            local ok, err, errno = self:step(timeout)
            if not ok then
                return nil, err, errno
            end
            return self:get_headers(deadline and deadline-cqueues.monotime())
        end
    end

    local ignore_fields = {
        [":authority"] = true;
        [":method"] = true;
        [":path"] = true;
        [":scheme"] = true;
        [":status"] = true;
        -- fields written manually in :write_headers
        ["connection"] = true;
        ["content-length"] = true;
        ["transfer-encoding"] = true;
    }
    -- Writes the given headers to the stream; optionally ends the stream at end of headers
    --
    -- We're free to insert any of the "Hop-by-hop" headers (as listed in RFC 2616 Section 13.5.1)
    -- Do this by directly writing the headers, rather than adding them to the passed headers object,
    -- as we don't want to modify the caller owned object.
    -- Note from RFC 7230 Appendix 2:
    --     "hop-by-hop" header fields are required to appear in the Connection header field;
    --     just because they're defined as hop-by-hop doesn't exempt them.
    function stream:write_headers(headers, end_stream, timeout)
        local deadline = timeout and (cqueues.monotime()+timeout)
        assert(headers, "missing argument: headers")
        -- Validate up front
        local connection_header = headers:get("connection")
        local transfer_encoding_header = headers:get("transfer-encoding")
        assert(type(end_stream) == "boolean", "'end_stream' MUST be a boolean")
        if self.state == "closed" or self.state == "half closed (local)" or self.connection.socket == nil then
            return nil, ce.strerror(ce.EPIPE), ce.EPIPE
        end
        local status_code, method
        local is_trailers
        if self.body_write_type == "chunked" then
            -- we are writing trailers; close off body
            is_trailers = true
            local ok, err, errno = self.connection:write_body_last_chunk(nil, 0)
            if not ok then return nil, err, errno end
        elseif self.type == "server" then
            if self.state == "idle" then
                error("cannot write headers when stream is idle")
            end
            status_code = headers:get(":status")
            -- RFC 7231 Section 6.2:
            -- Since HTTP/1.0 did not define any 1xx status codes, a server MUST NOT send a 1xx response to an HTTP/1.0 client.
            if status_code and status_code:sub(1,1) == "1" and self.peer_version < 1.1 then
                error("a server MUST NOT send a 1xx response to an HTTP/1.0 client")
            end
            -- Make sure we're at the front of the pipeline
            if self.connection.pipeline:peek() ~= self then
                assert(cqueues.running(), "cannot wait for condition if not within a cqueues coroutine")
                headers = headers:clone() -- don't want user to edit it and send wrong headers
                if cqueues.poll(self.pipeline_cond, timeout) == timeout then
                    return nil, ce.strerror(ce.ETIMEDOUT), ce.ETIMEDOUT
                end
                assert(self.connection.pipeline:peek() == self)
            end
            if status_code then
                -- Should send status line
                local reason_phrase = HTTP_STATUS[status_code]
                local version = math.min(self.connection.version, self.peer_version)
                local ok, err, errno = self.connection:write_status_line(version, status_code, reason_phrase, 0)
                if not ok then
                    return nil, err, errno
                end
            end
        else -- client
            if self.state == "idle" then
                method = assert(headers:get(":method"), "missing method")
                self.req_method = method
                local path
                if method == "CONNECT" then
                    path = assert(headers:get(":authority"), "missing authority")
                    assert(not headers:has(":path"), "CONNECT requests should not have a path")
                else
                    -- RFC 7230 Section 5.4: A client MUST send a Host header field in all HTTP/1.1 request messages.
                    assert(self.connection.version < 1.1 or headers:has(":authority"), "missing authority")
                    path = assert(headers:get(":path"), "missing path")
                end
                if self.connection.req_locked then
                    -- Wait until previous request has been fully written
                    assert(cqueues.running(), "cannot wait for condition if not within a cqueues coroutine")
                    headers = headers:clone() -- don't want user to edit it and send wrong headers
                    if cqueues.poll(self.connection.req_cond, timeout) == timeout then
                        return nil, ce.strerror(ce.ETIMEDOUT), ce.ETIMEDOUT
                    end
                    assert(self.connection.req_locked == nil)
                end
                self.connection.pipeline:push(self)
                self.connection.req_locked = self
                -- write request line
                local ok, err, errno = self.connection:write_request_line(method, path, self.connection.version, 0)
                if not ok then
                    return nil, err, errno
                end
                self:set_state("open")
            else
                assert(self.state == "open")
            end
        end
        local cl = headers:get("content-length") -- ignore subsequent content-length values
        if self.req_method == "CONNECT" and (self.type == "client" or status_code == "200") then
            -- successful CONNECT requests always continue until the connection is closed
            self.body_write_type = "close"
            self.close_when_done = true
            if self.type == "server" and (cl or transfer_encoding_header) then
                -- RFC 7231 Section 4.3.6:
                -- A server MUST NOT send any Transfer-Encoding or Content-Length header
                -- fields in a 2xx (Successful) response to CONNECT.
                error("Content-Length and Transfer-Encoding not allowed with successful CONNECT response")
            end
        elseif self.type == "server" and status_code and status_code:sub(1, 1) == "1" then
            assert(not end_stream, "cannot end stream directly after 1xx status code")
            -- A server MUST NOT send a Content-Length header field in any response
            -- with a status code of 1xx (Informational) or 204 (No Content)
            if cl then
                error("Content-Length not allowed in response with 1xx status code")
            end
            if status_code == "101" then
                self.body_write_type = "switched protocol"
            end
        elseif not self.body_write_type then -- only figure out how to send the body if we haven't figured it out yet... TODO: use better check
            if self.close_when_done == nil then
                if self.connection.version == 1.0 or (self.type == "server" and self.peer_version == 1.0) then
                    self.close_when_done = not connection_header == 'keep-alive' --util.has(connection_header, "keep-alive")
                else
                    self.close_when_done = connection_header == 'close' -- util.has(connection_header, "close")
                end
            end
            if cl then
                -- RFC 7230 Section 3.3.2:
                -- A sender MUST NOT send a Content-Length header field in any
                -- message that contains a Transfer-Encoding header field.
                if transfer_encoding_header then
                    error("Content-Length not allowed in message with a transfer-encoding")
                elseif self.type == "server" then
                    -- A server MUST NOT send a Content-Length header field in any response
                    -- with a status code of 1xx (Informational) or 204 (No Content)
                    if status_code == "204" then
                        error("Content-Length not allowed in response with 204 status code")
                    end
                end
            end
            if end_stream then
                -- Make sure 'end_stream' is respected
                if self.type == "server" and (self.req_method == "HEAD" or status_code == "304") then
                    self.body_write_type = "missing"
                elseif transfer_encoding_header == 'chunked' then
                    self.body_write_type = "chunked"
                else
                    -- By adding `content-length: 0` we can be sure that our peer won't wait for a body
                    -- This is somewhat suggested in RFC 7231 section 8.1.2
                    if cl then -- might already have content-length: 0
                        assert(cl:match("^ *0+ *$"), "cannot end stream after headers if you have a non-zero content-length")
                    elseif self.type ~= "client" or (method ~= "GET" and method ~= "HEAD") then
                        cl = "0"
                    end
                    self.body_write_type = "length"
                    self.body_write_left = 0
                end
            else
                -- The order of these checks matter:
                    -- chunked must be checked first, as it totally changes the body format
                    -- content-length is next
                    -- closing the connection is ordered after length
                        -- this potentially means an early EOF can be caught if a connection
                        -- closure occurs before body size reaches the specified length
                    -- for HTTP/1.1, we can fall-back to a chunked encoding
                        -- chunked is mandatory to implement in HTTP/1.1
                        -- this requires amending the transfer-encoding header
                    -- for an HTTP/1.0 server, we fall-back to closing the connection at the end of the stream
                    -- else is an HTTP/1.0 client with `connection: keep-alive` but no other header indicating the body form.
                        -- this cannot be reasonably handled, so throw an error.
                if transfer_encoding_header and transfer_encoding_header == "chunked" then
                    self.body_write_type = "chunked"
                elseif cl then
                    self.body_write_type = "length"
                    self.body_write_left = assert(tonumber(cl, 10), "invalid content-length")
                elseif self.close_when_done then -- ordered after length delimited
                    self.body_write_type = "close"
                elseif self.connection.version == 1.1 and (self.type == "client" or self.peer_version == 1.1) then
                    self.body_write_type = "chunked"
                    -- transfer-encodings are ordered. we need to make sure we place "chunked" last
                    transfer_encoding_header = 'chunked'
                elseif self.type == "server" then
                    -- default for servers if they don't send a particular header                    
                    self.body_write_type = "close"
                    self.close_when_done = true
                else
                    error("a client cannot send a body with connection: keep-alive without indicating body delimiter in headers")
                end
            end
            -- Add 'Connection: close' header if we're going to close after
            if self.close_when_done then connection_header = 'close' end 
        end
        for name, value in headers:each() do
            if not ignore_fields[name] then
                local ok, err, errno = self.connection:write_header(name, value, 0)
                if not ok then
                    return nil, err, errno
                end
            elseif name == ":authority" then
                -- for CONNECT requests, :authority is the path
                if self.req_method ~= "CONNECT" then
                    -- otherwise it's the Host header
                    local ok, err, errno = self.connection:write_header("host", value, 0)
                    if not ok then
                        return nil, err, errno
                    end
                end
            end
        end
        -- Write transfer-encoding, content-length and connection headers separately
        if transfer_encoding_header then
            local ok, err, errno = self.connection:write_header("transfer-encoding", transfer_encoding_header, 0)
            if not ok then return nil, err, errno end
        elseif cl then
            local ok, err, errno = self.connection:write_header("content-length", cl, 0)
            if not ok then return nil, err, errno end
        end
        if connection_header then
            local ok, err, errno = self.connection:write_header("connection", connection_header, 0)
            if not ok then return nil, err, errno end
        end

        do
            local ok, err, errno = self.connection:write_headers_done(deadline and (deadline-cqueues.monotime()))
            if not ok then return nil, err, errno end
        end

        if end_stream then
            if is_trailers then
                if self.state == "half closed (remote)" then
                    self:set_state("closed")
                else
                    self:set_state("half closed (local)")
                end
            else
                local ok, err, errno = self:write_chunk("", true)
                if not ok then
                    return nil, err, errno
                end
            end
        end

        return true
    end

    function stream:read_next_chunk(timeout)
        if self.state == "closed" or self.state == "half closed (remote)" then
            return nil
        end
        local end_stream
        local chunk, err, errno
        if self.body_read_type == "chunked" then
            local deadline = timeout and (cqueues.monotime()+timeout)
            if self.body_read_left == 0 then
                chunk = false
            else
                chunk, err, errno = self.connection:read_body_chunk(timeout)
            end
            if chunk == false then
                -- last chunk, :read_headers should be called to get trailers
                self.body_read_left = 0
                -- for API compat: attempt to read trailers
                local ok
                ok, err, errno = self:step(deadline and deadline-cqueues.monotime())
                if not ok then
                    return nil, err, errno
                end
                return nil
            else
                end_stream = false
                if chunk == nil and err == nil then
                    return nil, ce.strerror(ce.EPIPE), ce.EPIPE
                end
            end
        elseif self.body_read_type == "length" then
            local length_n = self.body_read_left
            if length_n > 0 then
                -- Read *upto* length_n bytes
                -- This function only has to read chunks; not the whole body
                chunk, err, errno = self.connection:read_body_by_length(-length_n, timeout)
                if chunk ~= nil then
                    self.body_read_left = length_n - #chunk
                    end_stream = (self.body_read_left == 0)
                end
            elseif length_n == 0 then
                chunk = ""
                end_stream = true
            else
                error("invalid length: "..tostring(length_n))
            end
        elseif self.body_read_type == "close" then
            -- Use a big negative number instead of *a. see https://github.com/wahern/cqueues/issues/89
            chunk, err, errno = self.connection:read_body_by_length(-0x80000000, timeout)
            end_stream = chunk == nil and err == nil
        elseif self.body_read_type == nil then
            -- Might get here if haven't read headers yet, or if only headers so far have been 1xx codes
            local deadline = timeout and (cqueues.monotime()+timeout)
            local headers
            headers, err, errno = self:read_headers(timeout)
            if not headers then
                return nil, err, errno
            end
            self.headers_fifo:push(headers)
            self.headers_cond:signal(1)
            return self:get_next_chunk(deadline and deadline-cqueues.monotime())
        else
            error("unknown body read type")
        end
        if chunk then
            if self.body_read_inflate then
                chunk = self.body_read_inflate(chunk, end_stream)
            end
            self.stats_recv = self.stats_recv + #chunk
        end
        if end_stream then
            if self.state == "half closed (local)" then
                self:set_state("closed")
            else
                self:set_state("half closed (remote)")
            end
        end
        return chunk, err, errno
    end

    function stream:get_next_chunk(timeout)
        if self.chunk_fifo:length() > 0 then
            return self.chunk_fifo:pop()
        end
        return self:read_next_chunk(timeout)
    end

    function stream:unget(str)
        self.chunk_fifo:insert(1, str)
        self.chunk_cond:signal()
        return true
    end

    local empty_headers = headers_new()
    function stream:write_chunk(chunk, end_stream, timeout)
        if self.state == "idle" then
            error("cannot write chunk when stream is " .. self.state)
        elseif self.state == "closed" or self.state == "half closed (local)" or self.connection.socket == nil then
            return nil, ce.strerror(ce.EPIPE), ce.EPIPE
        elseif self.body_write_type == nil then
            error("cannot write body before headers")
        end
        if self.type == "client" then
            assert(self.connection.req_locked == self)
        else
            assert(self.connection.pipeline:peek() == self)
        end
        local orig_size = #chunk
        if self.body_write_deflate then
            chunk = self.body_write_deflate(chunk, end_stream)
        end
        if #chunk > 0 then
            if self.body_write_type == "chunked" then
                local deadline = timeout and cqueues.monotime()+timeout
                local ok, err, errno = self.connection:write_body_chunk(chunk, nil, timeout)
                if not ok then
                    return nil, err, errno
                end
                timeout = deadline and (deadline-cqueues.monotime())
            elseif self.body_write_type == "length" then
                assert(self.body_write_left >= #chunk, "invalid content-length")
                local ok, err, errno = self.connection:write_body_plain(chunk, timeout)
                if not ok then
                    return nil, err, errno
                end
                self.body_write_left = self.body_write_left - #chunk
            elseif self.body_write_type == "close" then
                local ok, err, errno = self.connection:write_body_plain(chunk, timeout)
                if not ok then
                    return nil, err, errno
                end
            elseif self.body_write_type ~= "missing" then
                error("unknown body writing method")
            end
        end
        self.stats_sent = self.stats_sent + orig_size
        if end_stream then
            if self.body_write_type == "chunked" then
                return self:write_headers(empty_headers, true, timeout)
            elseif self.body_write_type == "length" then
                assert(self.body_write_left == 0, "invalid content-length")
            end
            if self.state == "half closed (remote)" then
                self:set_state("closed")
            else
                self:set_state("half closed (local)")
            end
        end
        return true
    end
    
    function stream.new(connection)
        local self = setmetatable({
            connection = connection;
            type = connection.type;

            state = "idle";
            stats_sent = 0;
            stats_recv = 0;

            pipeline_cond = cc.new(); -- signalled when stream reaches front of pipeline

            req_method = nil; -- string
            peer_version = nil; -- 1.0 or 1.1
            has_main_headers = false;
            headers_in_progress = nil;
            headers_fifo = fifo.new();
            headers_cond = cc.new();
            chunk_fifo = fifo.new();
            chunk_cond = cc.new();
            body_write_type = nil; -- "closed", "chunked", "length" or "missing"
            body_write_left = nil; -- integer: only set when body_write_type == "length"
            body_write_deflate_encoding = nil;
            body_write_deflate = nil; -- nil or stateful deflate closure
            body_read_type = nil;
            body_read_inflate = nil;
            close_when_done = nil; -- boolean
        }, stream_mt)
        return self
    end

end

-- This module implements the socket level for HTTP connections
local conn = {}
do
    local conn_mt = {
        __name = "http.connection";
        __index = conn;
        __tostring = function() return string.format("http.connection{version=1.1}") end 
    }
    function conn.onerror(socket, op, why, lvl) -- luacheck: ignore 212
        local err = string.format("%s: %s", op, ce.strerror(why))
        if op == "starttls" then
            local ssl = socket:checktls()
            if ssl and ssl.getVerifyResult then
                local code, msg = ssl:getVerifyResult()
                if code ~= 0 then
                    err = err .. ":" .. msg
                end
            end
        end
        if why == ce.ETIMEDOUT then
            if op == "fill" or op == "read" then
                socket:clearerr("r")
            elseif op == "flush" then
                socket:clearerr("w")
            end
        end
        return err, why
    end

    function conn:pollfd()
        if self.socket == nil then
            return nil
        end
        return self.socket:pollfd()
    end

    function conn:events()
        if self.socket == nil then
            return nil
        end
        return self.socket:events()
    end

    function conn:timeout()
        if self.socket == nil then
            return nil
        end
        return self.socket:timeout()
    end

    function conn:onidle_() -- luacheck: ignore 212
    end

    function conn:onidle(...)
        local old_handler = self.onidle_
        if select("#", ...) > 0 then
            self.onidle_ = ...
        end
        return old_handler
    end

    function conn:connect(timeout)
        if self.socket == nil then
            return nil
        end
        local ok, err, errno = self.socket:connect(timeout)
        if not ok then
            return nil, err, errno
        end
        return true
    end

    function conn:checktls()
        if self.socket == nil then
            return nil
        end
        return self.socket:checktls()
    end

    function conn:localname()
        if self.socket == nil then
            return nil
        end
        return ca.fileresult(self.socket:localname())
    end

    function conn:peername()
        if self.socket == nil then
            return nil
        end
        return ca.fileresult(self.socket:peername())
    end

    -- Primarily used for testing
    function conn:flush(timeout)
        return self.socket:flush("n", timeout)
    end

    function conn:close()
        self:shutdown()
        if self.socket then
            cqueues.poll()
            cqueues.poll()
            self.socket:close()
        end
        return true
    end

    function conn:setmaxline(read_length)
        if self.socket == nil then
            return nil
        end
        self.socket:setmaxline(read_length)
        return true
    end

    function conn:clearerr(...)
        if self.socket == nil then
            return nil
        end
        return self.socket:clearerr(...)
    end

    function conn:error(...)
        if self.socket == nil then
            return nil
        end
        return self.socket:error(...)
    end

    function conn:take_socket()
        local s = self.socket
        if s == nil then
            -- already taken
            return nil
        end
        self.socket = nil
        -- Shutdown *after* taking away socket so shutdown handlers can't effect the socket
        self:shutdown()
        -- Reset socket to some defaults
        s:onerror(nil)
        return s
    end

    function conn:shutdown(dir)
        if dir == nil or dir:match("w") then
            while self.pipeline:length() > 0 do
                local stream = self.pipeline:peek()
                stream:shutdown()
            end
        end
        if self.socket then
            return ca.fileresult(self.socket:shutdown(dir))
        else
            return true
        end
    end

    function conn:new_stream()
        assert(self.type == "client")
        if self.socket == nil or self.socket:eof("w") then
            return nil
        end
        local stream = stream.new(self)
        return stream
    end

    -- this function *should never throw*
    function conn:get_next_incoming_stream(timeout)
        assert(self.type == "server")
        -- Make sure we don't try and read before the previous request has been fully read
        if self.req_locked then
            local deadline = timeout and cqueues.monotime()+timeout
            assert(cqueues.running(), "cannot wait for condition if not within a cqueues coroutine")
            if cqueues.poll(self.req_cond, timeout) == timeout then
                return nil, ce.strerror(ce.ETIMEDOUT), ce.ETIMEDOUT
            end
            timeout = deadline and deadline-cqueues.monotime()
            assert(self.req_locked == nil)
        end
        if self.socket == nil then
            return nil
        end
        -- Wait for at least one byte
        local ok, err, errno = self.socket:fill(1, 0)
        if not ok then
            if errno == ce.ETIMEDOUT then
                local deadline = timeout and cqueues.monotime()+timeout
                if cqueues.poll(self.socket, timeout) ~= timeout then
                    return self:get_next_incoming_stream(deadline and deadline-cqueues.monotime())
                end
            end
            return nil, err, errno
        end
        local stream = stream.new(self)
        self.pipeline:push(stream)
        self.req_locked = stream
        return stream
    end

    function conn:read_request_line(timeout)
        local deadline = timeout and (cqueues.monotime()+timeout)
        local preline
        local line, err, errno = self.socket:xread("*L", timeout)
        if line == "\r\n" then
            -- RFC 7230 3.5: a server that is expecting to receive and parse a request-line
            -- SHOULD ignore at least one empty line (CRLF) received prior to the request-line.
            preline = line
            line, err, errno = self.socket:xread("*L", deadline and (deadline-cqueues.monotime()))
        end
        if line == nil then
            if preline then
                local ok, errno2 = self.socket:unget(preline)
                if not ok then
                    return nil, conn.onerror(self.socket, "unget", errno2)
                end
            end
            return nil, err, errno
        end
        local method, path, httpversion = line:match("^(%w+) (%S+) HTTP/(1%.[01])\r\n$")
        if not method then
            self.socket:seterror("r", ce.EILSEQ)
            local ok, errno2 = self.socket:unget(line)
            if not ok then
                return nil, conn.onerror(self.socket, "unget", errno2)
            end
            if preline then
                ok, errno2 = self.socket:unget(preline)
                if not ok then
                    return nil, conn.onerror(self.socket, "unget", errno2)
                end
            end
            return nil, conn.onerror(self.socket, "read_request_line", ce.EILSEQ)
        end
        httpversion = httpversion == "1.0" and 1.0 or 1.1 -- Avoid tonumber() due to locale issues
        return method, path, httpversion
    end

    function conn:read_status_line(timeout)
        local line, err, errno = self.socket:xread("*L", timeout)
        if line == nil then
            return nil, err, errno
        end
        local httpversion, status_code, reason_phrase = line:match("^HTTP/(1%.[01]) (%d%d%d) (.*)\r\n$")
        if not httpversion then
            self.socket:seterror("r", ce.EILSEQ)
            local ok, errno2 = self.socket:unget(line)
            if not ok then
                return nil, conn.onerror(self.socket, "unget", errno2)
            end
            return nil, conn.onerror(self.socket, "read_status_line", ce.EILSEQ)
        end
        httpversion = httpversion == "1.0" and 1.0 or 1.1 -- Avoid tonumber() due to locale issues
        return httpversion, status_code, reason_phrase
    end

    function conn:read_header(timeout)
        local line, err, errno = self.socket:xread("*h", timeout)
        if line == nil then
            -- Note: the *h read returns *just* nil when data is a non-mime compliant header
            if err == nil then
                local pending_bytes = self.socket:pending()
                -- check if we're at end of headers
                if pending_bytes >= 2 then
                    local peek = assert(self.socket:xread(2, "b", 0))
                    local ok, errno2 = self.socket:unget(peek)
                    if not ok then
                        return nil, conn.onerror(self.socket, "unget", errno2)
                    end
                    if peek == "\r\n" then
                        return nil
                    end
                end
                if pending_bytes > 0 then
                    self.socket:seterror("r", ce.EILSEQ)
                    return nil, conn.onerror(self.socket, "read_header", ce.EILSEQ)
                end
            end
            return nil, err, errno
        end
        -- header fields can have optional surrounding whitespace
        --[[ RFC 7230 3.2.4: No whitespace is allowed between the header field-name
        and colon. In the past, differences in the handling of such whitespace have
        led to security vulnerabilities in request routing and response handling.
        A server MUST reject any received request message that contains whitespace
        between a header field-name and colon with a response code of
        400 (Bad Request). A proxy MUST remove any such whitespace from a response
        message before forwarding the message downstream.]]
        local key, val = line:match("^([^%s:]+):[ \t]*(.-)[ \t]*$")
        if not key then
            self.socket:seterror("r", ce.EILSEQ)
            local ok, errno2 = self.socket:unget(line)
            if not ok then
                return nil, conn.onerror(self.socket, "unget", errno2)
            end
            return nil, conn.onerror(self.socket, "read_header", ce.EILSEQ)
        end
        return key, val
    end

    function conn:read_headers_done(timeout)
        local crlf, err, errno = self.socket:xread(2, timeout)
        if crlf == "\r\n" then
            return true
        elseif crlf ~= nil or (err == nil and self.socket:pending() > 0) then
            self.socket:seterror("r", ce.EILSEQ)
            if crlf then
                local ok, errno2 = self.socket:unget(crlf)
                if not ok then
                    return nil, conn.onerror(self.socket, "unget", errno2)
                end
            end
            return nil, conn.onerror(self.socket, "read_headers_done", ce.EILSEQ)
        else
            return nil, err, errno
        end
    end

    -- pass a negative length for *up to* that number of bytes
    function conn:read_body_by_length(len, timeout)
        assert(type(len) == "number")
        return self.socket:xread(len, timeout)
    end

    function conn:read_body_till_close(timeout)
        return self.socket:xread("*a", timeout)
    end

    function conn:read_body_chunk(timeout)
        local deadline = timeout and (cqueues.monotime()+timeout)
        local chunk_header, err, errno = self.socket:xread("*L", timeout)
        if chunk_header == nil then
            return nil, err, errno
        end
        local chunk_size, chunk_ext = chunk_header:match("^(%x+) *(.-)\r\n")
        if chunk_size == nil then
            self.socket:seterror("r", ce.EILSEQ)
            local unget_ok1, unget_errno1 = self.socket:unget(chunk_header)
            if not unget_ok1 then
                return nil, conn.onerror(self.socket, "unget", unget_errno1)
            end
            return nil, conn.onerror(self.socket, "read_body_chunk", ce.EILSEQ)
        elseif #chunk_size > 8 then
            self.socket:seterror("r", ce.E2BIG)
            return nil, conn.onerror(self.socket, "read_body_chunk", ce.E2BIG)
        end
        chunk_size = tonumber(chunk_size, 16)
        if chunk_ext == "" then
            chunk_ext = nil
        end
        if chunk_size == 0 then
            -- you MUST read trailers after this!
            return false, chunk_ext
        else
            local ok, err2, errno2 = self.socket:fill(chunk_size+2, 0)
            if not ok then
                local unget_ok1, unget_errno1 = self.socket:unget(chunk_header)
                if not unget_ok1 then
                    return nil, conn.onerror(self.socket, "unget", unget_errno1)
                end
                if errno2 == ce.ETIMEDOUT then
                    timeout = deadline and deadline-cqueues.monotime()
                    if cqueues.poll(self.socket, timeout) ~= timeout then
                        -- retry
                        return self:read_body_chunk(deadline and deadline-cqueues.monotime())
                    end
                elseif err2 == nil then
                    self.socket:seterror("r", ce.EILSEQ)
                    return nil, conn.onerror(self.socket, "read_body_chunk", ce.EILSEQ)
                end
                return nil, err2, errno2
            end
            -- if `fill` succeeded these shouldn't be able to fail
            local chunk_data = assert(self.socket:xread(chunk_size, "b", 0))
            local crlf = assert(self.socket:xread(2, "b", 0))
            if crlf ~= "\r\n" then
                self.socket:seterror("r", ce.EILSEQ)
                local unget_ok3, unget_errno3 = self.socket:unget(crlf)
                if not unget_ok3 then
                    return nil, conn.onerror(self.socket, "unget", unget_errno3)
                end
                local unget_ok2, unget_errno2 = self.socket:unget(chunk_data)
                if not unget_ok2 then
                    return nil, conn.onerror(self.socket, "unget", unget_errno2)
                end
                local unget_ok1, unget_errno1 = self.socket:unget(chunk_header)
                if not unget_ok1 then
                    return nil, conn.onerror(self.socket, "unget", unget_errno1)
                end
                return nil, conn.onerror(self.socket, "read_body_chunk", ce.EILSEQ)
            end
            -- Success!
            return chunk_data, chunk_ext
        end
    end

    function conn:write_request_line(method, path, httpversion, timeout)
        assert(method:match("^[^ \r\n]+$"))
        assert(path:match("^[^ \r\n]+$"))
        assert(httpversion == 1.0 or httpversion == 1.1)
        local line = string.format("%s %s HTTP/%s\r\n", method, path, httpversion == 1.0 and "1.0" or "1.1")
        local ok, err, errno = self.socket:xwrite(line, "f", timeout)
        if not ok then
            return nil, err, errno
        end
        return true
    end

    function conn:write_status_line(httpversion, status_code, reason_phrase, timeout)
        assert(httpversion == 1.0 or httpversion == 1.1)
        assert(status_code:match("^[1-9]%d%d$"), "invalid status code")
        assert(type(reason_phrase) == "string" and reason_phrase:match("^[^\r\n]*$"), "invalid reason phrase")
        local line = string.format("HTTP/%s %s %s\r\n", httpversion == 1.0 and "1.0" or "1.1", status_code, reason_phrase)
        local ok, err, errno = self.socket:xwrite(line, "f", timeout)
        if not ok then
            return nil, err, errno
        end
        return true
    end

    function conn:write_header(k, v, timeout)
        v = tostring(v)
        assert(type(k) == "string" and k:match("^[^:\r\n]+$"), "field name invalid")
        assert(type(v) == "string" and v:sub(-1, -1) ~= "\n" and not v:match("\n[^ ]"), "field value invalid")
        local ok, err, errno = self.socket:xwrite(k..": "..v.."\r\n", "f", timeout)
        if not ok then
            return nil, err, errno
        end
        return true
    end

    function conn:write_headers_done(timeout)
        -- flushes write buffer
        local ok, err, errno = self.socket:xwrite("\r\n", "n", timeout)
        if not ok then
            return nil, err, errno
        end
        return true
    end

    function conn:write_body_chunk(chunk, chunk_ext, timeout)
        assert(chunk_ext == nil, "chunk extensions not supported")
        local data = string.format("%x\r\n", #chunk) .. chunk .. "\r\n"
        -- flushes write buffer
        local ok, err, errno = self.socket:xwrite(data, "n", timeout)
        if not ok then
            return nil, err, errno
        end
        return true
    end

    function conn:write_body_last_chunk(chunk_ext, timeout)
        assert(chunk_ext == nil, "chunk extensions not supported")
        -- no flush; writing trailers (via write_headers_done) will do that
        local ok, err, errno = self.socket:xwrite("0\r\n", "f", timeout)
        if not ok then
            return nil, err, errno
        end
        return true
    end

    function conn:write_body_plain(body, timeout)
        -- flushes write buffer
        local ok, err, errno = self.socket:xwrite(body, "n", timeout)
        if not ok then
            return nil, err, errno
        end
        return true
    end

    -- assumes ownership of the socket
    function conn.new(socket, conn_type, version)
        assert(socket, "must provide a socket")
        if conn_type ~= "client" and conn_type ~= "server" then
            error('invalid connection type. must be "client" or "server"')
        end
        assert(version == 1 or version == 1.1, "unsupported version")
        local self = setmetatable({
            socket = socket;
            type = conn_type;
            version = version;

            -- for server: streams waiting to go out
            -- for client: streams waiting for a response
            pipeline = fifo.new();
            -- pipeline condition is stored in stream itself

            -- for server: held while request being read
            -- for client: held while writing request
            req_locked = nil;
            -- signaled when unlocked
            req_cond = cc.new();

            -- A function that will be called if the connection becomes idle
            onidle_ = nil;
        }, conn_mt)
        socket:setvbuf("full", math.huge) -- 'infinite' buffering; no write locks needed
        socket:setmode("b", "bf")
        socket:onerror(conn.onerror)
        return self
    end
end

-- This module implements TLS
local https = {}
do
    https.has_hostname_validation = openssl.x509.verify_param.new().setHost ~= nil

    -- Cipher lists from Mozilla.
    -- https://wiki.mozilla.org/Security/Server_Side_TLS
    -- This list of ciphers should be kept up to date.

    -- "Modern" cipher list
    local modern_cipher_list = table.concat({"ECDHE-ECDSA-AES256-GCM-SHA384"; "ECDHE-RSA-AES256-GCM-SHA384"; "ECDHE-ECDSA-CHACHA20-POLY1305"; "ECDHE-RSA-CHACHA20-POLY1305"; "ECDHE-ECDSA-AES128-GCM-SHA256"; 
                                            "ECDHE-RSA-AES128-GCM-SHA256"; "ECDHE-ECDSA-AES256-SHA384"; "ECDHE-RSA-AES256-SHA384"; "ECDHE-ECDSA-AES128-SHA256"; "ECDHE-RSA-AES128-SHA256";}, ':')

    -- "Intermediate" cipher list
    local intermediate_cipher_list = table.concat({"ECDHE-ECDSA-CHACHA20-POLY1305";"ECDHE-RSA-CHACHA20-POLY1305";"ECDHE-ECDSA-AES128-GCM-SHA256";"ECDHE-RSA-AES128-GCM-SHA256";"ECDHE-ECDSA-AES256-GCM-SHA384";
                                                  "ECDHE-RSA-AES256-GCM-SHA384";"DHE-RSA-AES128-GCM-SHA256";"DHE-RSA-AES256-GCM-SHA384";"ECDHE-ECDSA-AES128-SHA256";"ECDHE-RSA-AES128-SHA256";"ECDHE-ECDSA-AES128-SHA";
                                                  "ECDHE-RSA-AES256-SHA384";"ECDHE-RSA-AES128-SHA";"ECDHE-ECDSA-AES256-SHA384";"ECDHE-ECDSA-AES256-SHA";"ECDHE-RSA-AES256-SHA";"DHE-RSA-AES128-SHA256";"DHE-RSA-AES128-SHA";
                                                  "DHE-RSA-AES256-SHA256";"DHE-RSA-AES256-SHA";"ECDHE-ECDSA-DES-CBC3-SHA";"ECDHE-RSA-DES-CBC3-SHA";"EDH-RSA-DES-CBC3-SHA";"AES128-GCM-SHA256";"AES256-GCM-SHA384";
                                                  "AES128-SHA256";"AES256-SHA256";"AES128-SHA";"AES256-SHA";"DES-CBC3-SHA";"!DSS";}, ':')

    -- "Old" cipher list
    local old_cipher_list = table.concat({
        "ECDHE-ECDSA-CHACHA20-POLY1305";"ECDHE-RSA-CHACHA20-POLY1305";"ECDHE-RSA-AES128-GCM-SHA256";"ECDHE-ECDSA-AES128-GCM-SHA256";"ECDHE-RSA-AES256-GCM-SHA384";"ECDHE-ECDSA-AES256-GCM-SHA384";"DHE-RSA-AES128-GCM-SHA256";
        "DHE-DSS-AES128-GCM-SHA256";"kEDH+AESGCM";"ECDHE-RSA-AES128-SHA256";"ECDHE-ECDSA-AES128-SHA256";"ECDHE-RSA-AES128-SHA";"ECDHE-ECDSA-AES128-SHA";"ECDHE-RSA-AES256-SHA384";"ECDHE-ECDSA-AES256-SHA384";
        "ECDHE-RSA-AES256-SHA";"ECDHE-ECDSA-AES256-SHA";"DHE-RSA-AES128-SHA256";"DHE-RSA-AES128-SHA";"DHE-DSS-AES128-SHA256";"DHE-RSA-AES256-SHA256";"DHE-DSS-AES256-SHA";"DHE-RSA-AES256-SHA";"ECDHE-RSA-DES-CBC3-SHA";
        "ECDHE-ECDSA-DES-CBC3-SHA";"EDH-RSA-DES-CBC3-SHA";"AES128-GCM-SHA256";"AES256-GCM-SHA384";"AES128-SHA256";"AES256-SHA256";"AES128-SHA";"AES256-SHA";"AES";"DES-CBC3-SHA";"HIGH";"SEED";"!aNULL";"!eNULL";"!EXPORT";
        "!DES";"!RC4";"!MD5";"!PSK";"!RSAPSK";"!aDH";"!aECDH";"!EDH-DSS-DES-CBC3-SHA";"!KRB5-DES-CBC3-SHA";"!SRP";}, ':')

    -- A map from the cipher identifiers used in specifications to
    -- the identifiers used by OpenSSL.
    local spec_to_openssl = {
        -- SSL cipher suites
        SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA        = "DH-DSS-DES-CBC3-SHA";
        SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA        = "DH-RSA-DES-CBC3-SHA";
        SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA       = "DHE-DSS-DES-CBC3-SHA";
        SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA       = "DHE-RSA-DES-CBC3-SHA";
        SSL_DH_anon_WITH_RC4_128_MD5            = "ADH-RC4-MD5";
        SSL_DH_anon_WITH_3DES_EDE_CBC_SHA       = "ADH-DES-CBC3-SHA";

        -- TLS v1.0 cipher suites.
        TLS_RSA_WITH_NULL_MD5                   = "NULL-MD5";
        TLS_RSA_WITH_NULL_SHA                   = "NULL-SHA";
        TLS_RSA_WITH_RC4_128_MD5                = "RC4-MD5";
        TLS_RSA_WITH_RC4_128_SHA                = "RC4-SHA";
        TLS_RSA_WITH_IDEA_CBC_SHA               = "IDEA-CBC-SHA";
        TLS_RSA_WITH_DES_CBC_SHA                = "DES-CBC-SHA";
        TLS_RSA_WITH_3DES_EDE_CBC_SHA           = "DES-CBC3-SHA";
        TLS_DH_DSS_WITH_DES_CBC_SHA             = "DH-DSS-DES-CBC-SHA";
        TLS_DH_RSA_WITH_DES_CBC_SHA             = "DH-RSA-DES-CBC-SHA";
        TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA        = "DH-DSS-DES-CBC3-SHA";
        TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA        = "DH-RSA-DES-CBC3-SHA";
        TLS_DHE_DSS_WITH_DES_CBC_SHA            = "EDH-DSS-DES-CBC-SHA";
        TLS_DHE_RSA_WITH_DES_CBC_SHA            = "EDH-RSA-DES-CBC-SHA";
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA       = "DHE-DSS-DES-CBC3-SHA";
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA       = "DHE-RSA-DES-CBC3-SHA";
        TLS_DH_anon_WITH_RC4_128_MD5            = "ADH-RC4-MD5";
        TLS_DH_anon_WITH_DES_CBC_SHA            = "ADH-DES-CBC-SHA";
        TLS_DH_anon_WITH_3DES_EDE_CBC_SHA       = "ADH-DES-CBC3-SHA";

        -- AES ciphersuites from RFC3268, extending TLS v1.0
        TLS_RSA_WITH_AES_128_CBC_SHA            = "AES128-SHA";
        TLS_RSA_WITH_AES_256_CBC_SHA            = "AES256-SHA";
        TLS_DH_DSS_WITH_AES_128_CBC_SHA         = "DH-DSS-AES128-SHA";
        TLS_DH_DSS_WITH_AES_256_CBC_SHA         = "DH-DSS-AES256-SHA";
        TLS_DH_RSA_WITH_AES_128_CBC_SHA         = "DH-RSA-AES128-SHA";
        TLS_DH_RSA_WITH_AES_256_CBC_SHA         = "DH-RSA-AES256-SHA";
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA        = "DHE-DSS-AES128-SHA";
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA        = "DHE-DSS-AES256-SHA";
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA        = "DHE-RSA-AES128-SHA";
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA        = "DHE-RSA-AES256-SHA";
        TLS_DH_anon_WITH_AES_128_CBC_SHA        = "ADH-AES128-SHA";
        TLS_DH_anon_WITH_AES_256_CBC_SHA        = "ADH-AES256-SHA";


        -- Camellia ciphersuites from RFC4132, extending TLS v1.0

        TLS_RSA_WITH_CAMELLIA_128_CBC_SHA       = "CAMELLIA128-SHA";
        TLS_RSA_WITH_CAMELLIA_256_CBC_SHA       = "CAMELLIA256-SHA";
        TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA    = "DH-DSS-CAMELLIA128-SHA";
        TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA    = "DH-DSS-CAMELLIA256-SHA";
        TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA    = "DH-RSA-CAMELLIA128-SHA";
        TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA    = "DH-RSA-CAMELLIA256-SHA";
        TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA   = "DHE-DSS-CAMELLIA128-SHA";
        TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA   = "DHE-DSS-CAMELLIA256-SHA";
        TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA   = "DHE-RSA-CAMELLIA128-SHA";
        TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA   = "DHE-RSA-CAMELLIA256-SHA";
        TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA   = "ADH-CAMELLIA128-SHA";
        TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA   = "ADH-CAMELLIA256-SHA";


        -- SEED ciphersuites from RFC4162, extending TLS v1.0

        TLS_RSA_WITH_SEED_CBC_SHA               = "SEED-SHA";
        TLS_DH_DSS_WITH_SEED_CBC_SHA            = "DH-DSS-SEED-SHA";
        TLS_DH_RSA_WITH_SEED_CBC_SHA            = "DH-RSA-SEED-SHA";
        TLS_DHE_DSS_WITH_SEED_CBC_SHA           = "DHE-DSS-SEED-SHA";
        TLS_DHE_RSA_WITH_SEED_CBC_SHA           = "DHE-RSA-SEED-SHA";
        TLS_DH_anon_WITH_SEED_CBC_SHA           = "ADH-SEED-SHA";


        -- GOST ciphersuites from draft-chudov-cryptopro-cptls, extending TLS v1.0

        TLS_GOSTR341094_WITH_28147_CNT_IMIT = "GOST94-GOST89-GOST89";
        TLS_GOSTR341001_WITH_28147_CNT_IMIT = "GOST2001-GOST89-GOST89";
        TLS_GOSTR341094_WITH_NULL_GOSTR3411 = "GOST94-NULL-GOST94";
        TLS_GOSTR341001_WITH_NULL_GOSTR3411 = "GOST2001-NULL-GOST94";
        TLS_DHE_DSS_WITH_RC4_128_SHA            = "DHE-DSS-RC4-SHA";


        -- Elliptic curve cipher suites.

        TLS_ECDH_RSA_WITH_NULL_SHA              = "ECDH-RSA-NULL-SHA";
        TLS_ECDH_RSA_WITH_RC4_128_SHA           = "ECDH-RSA-RC4-SHA";
        TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA      = "ECDH-RSA-DES-CBC3-SHA";
        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA       = "ECDH-RSA-AES128-SHA";
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA       = "ECDH-RSA-AES256-SHA";

        TLS_ECDH_ECDSA_WITH_NULL_SHA            = "ECDH-ECDSA-NULL-SHA";
        TLS_ECDH_ECDSA_WITH_RC4_128_SHA         = "ECDH-ECDSA-RC4-SHA";
        TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA    = "ECDH-ECDSA-DES-CBC3-SHA";
        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA     = "ECDH-ECDSA-AES128-SHA";
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA     = "ECDH-ECDSA-AES256-SHA";

        TLS_ECDHE_RSA_WITH_NULL_SHA             = "ECDHE-RSA-NULL-SHA";
        TLS_ECDHE_RSA_WITH_RC4_128_SHA          = "ECDHE-RSA-RC4-SHA";
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA     = "ECDHE-RSA-DES-CBC3-SHA";
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA      = "ECDHE-RSA-AES128-SHA";
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA      = "ECDHE-RSA-AES256-SHA";

        TLS_ECDHE_ECDSA_WITH_NULL_SHA           = "ECDHE-ECDSA-NULL-SHA";
        TLS_ECDHE_ECDSA_WITH_RC4_128_SHA        = "ECDHE-ECDSA-RC4-SHA";
        TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA   = "ECDHE-ECDSA-DES-CBC3-SHA";
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA    = "ECDHE-ECDSA-AES128-SHA";
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA    = "ECDHE-ECDSA-AES256-SHA";

        TLS_ECDH_anon_WITH_NULL_SHA             = "AECDH-NULL-SHA";
        TLS_ECDH_anon_WITH_RC4_128_SHA          = "AECDH-RC4-SHA";
        TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA     = "AECDH-DES-CBC3-SHA";
        TLS_ECDH_anon_WITH_AES_128_CBC_SHA      = "AECDH-AES128-SHA";
        TLS_ECDH_anon_WITH_AES_256_CBC_SHA      = "AECDH-AES256-SHA";


        -- TLS v1.2 cipher suites

        TLS_RSA_WITH_NULL_SHA256                  = "NULL-SHA256";

        TLS_RSA_WITH_AES_128_CBC_SHA256           = "AES128-SHA256";
        TLS_RSA_WITH_AES_256_CBC_SHA256           = "AES256-SHA256";
        TLS_RSA_WITH_AES_128_GCM_SHA256           = "AES128-GCM-SHA256";
        TLS_RSA_WITH_AES_256_GCM_SHA384           = "AES256-GCM-SHA384";

        TLS_DH_RSA_WITH_AES_128_CBC_SHA256        = "DH-RSA-AES128-SHA256";
        TLS_DH_RSA_WITH_AES_256_CBC_SHA256        = "DH-RSA-AES256-SHA256";
        TLS_DH_RSA_WITH_AES_128_GCM_SHA256        = "DH-RSA-AES128-GCM-SHA256";
        TLS_DH_RSA_WITH_AES_256_GCM_SHA384        = "DH-RSA-AES256-GCM-SHA384";

        TLS_DH_DSS_WITH_AES_128_CBC_SHA256        = "DH-DSS-AES128-SHA256";
        TLS_DH_DSS_WITH_AES_256_CBC_SHA256        = "DH-DSS-AES256-SHA256";
        TLS_DH_DSS_WITH_AES_128_GCM_SHA256        = "DH-DSS-AES128-GCM-SHA256";
        TLS_DH_DSS_WITH_AES_256_GCM_SHA384        = "DH-DSS-AES256-GCM-SHA384";

        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256       = "DHE-RSA-AES128-SHA256";
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256       = "DHE-RSA-AES256-SHA256";
        TLS_DHE_RSA_WITH_AES_128_GCM_SHA256       = "DHE-RSA-AES128-GCM-SHA256";
        TLS_DHE_RSA_WITH_AES_256_GCM_SHA384       = "DHE-RSA-AES256-GCM-SHA384";

        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256       = "DHE-DSS-AES128-SHA256";
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256       = "DHE-DSS-AES256-SHA256";
        TLS_DHE_DSS_WITH_AES_128_GCM_SHA256       = "DHE-DSS-AES128-GCM-SHA256";
        TLS_DHE_DSS_WITH_AES_256_GCM_SHA384       = "DHE-DSS-AES256-GCM-SHA384";

        TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256      = "ECDH-RSA-AES128-SHA256";
        TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384      = "ECDH-RSA-AES256-SHA384";
        TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256      = "ECDH-RSA-AES128-GCM-SHA256";
        TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384      = "ECDH-RSA-AES256-GCM-SHA384";

        TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256    = "ECDH-ECDSA-AES128-SHA256";
        TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384    = "ECDH-ECDSA-AES256-SHA384";
        TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256    = "ECDH-ECDSA-AES128-GCM-SHA256";
        TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384    = "ECDH-ECDSA-AES256-GCM-SHA384";

        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256     = "ECDHE-RSA-AES128-SHA256";
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384     = "ECDHE-RSA-AES256-SHA384";
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256     = "ECDHE-RSA-AES128-GCM-SHA256";
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384     = "ECDHE-RSA-AES256-GCM-SHA384";

        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256   = "ECDHE-ECDSA-AES128-SHA256";
        TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384   = "ECDHE-ECDSA-AES256-SHA384";
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256   = "ECDHE-ECDSA-AES128-GCM-SHA256";
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384   = "ECDHE-ECDSA-AES256-GCM-SHA384";

        TLS_DH_anon_WITH_AES_128_CBC_SHA256       = "ADH-AES128-SHA256";
        TLS_DH_anon_WITH_AES_256_CBC_SHA256       = "ADH-AES256-SHA256";
        TLS_DH_anon_WITH_AES_128_GCM_SHA256       = "ADH-AES128-GCM-SHA256";
        TLS_DH_anon_WITH_AES_256_GCM_SHA384       = "ADH-AES256-GCM-SHA384";

        TLS_RSA_WITH_AES_128_CCM                  = "AES128-CCM";
        TLS_RSA_WITH_AES_256_CCM                  = "AES256-CCM";
        TLS_DHE_RSA_WITH_AES_128_CCM              = "DHE-RSA-AES128-CCM";
        TLS_DHE_RSA_WITH_AES_256_CCM              = "DHE-RSA-AES256-CCM";
        TLS_RSA_WITH_AES_128_CCM_8                = "AES128-CCM8";
        TLS_RSA_WITH_AES_256_CCM_8                = "AES256-CCM8";
        TLS_DHE_RSA_WITH_AES_128_CCM_8            = "DHE-RSA-AES128-CCM8";
        TLS_DHE_RSA_WITH_AES_256_CCM_8            = "DHE-RSA-AES256-CCM8";
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM          = "ECDHE-ECDSA-AES128-CCM";
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM          = "ECDHE-ECDSA-AES256-CCM";
        TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8        = "ECDHE-ECDSA-AES128-CCM8";
        TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8        = "ECDHE-ECDSA-AES256-CCM8";


        -- Camellia HMAC-Based ciphersuites from RFC6367, extending TLS v1.2

        TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 = "ECDHE-ECDSA-CAMELLIA128-SHA256";
        TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 = "ECDHE-ECDSA-CAMELLIA256-SHA384";
        TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  = "ECDH-ECDSA-CAMELLIA128-SHA256";
        TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  = "ECDH-ECDSA-CAMELLIA256-SHA384";
        TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256   = "ECDHE-RSA-CAMELLIA128-SHA256";
        TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384   = "ECDHE-RSA-CAMELLIA256-SHA384";
        TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256    = "ECDH-RSA-CAMELLIA128-SHA256";
        TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384    = "ECDH-RSA-CAMELLIA256-SHA384";


        -- Pre shared keying (PSK) ciphersuites

        TLS_PSK_WITH_NULL_SHA                         = "PSK-NULL-SHA";
        TLS_DHE_PSK_WITH_NULL_SHA                     = "DHE-PSK-NULL-SHA";
        TLS_RSA_PSK_WITH_NULL_SHA                     = "RSA-PSK-NULL-SHA";

        TLS_PSK_WITH_RC4_128_SHA                      = "PSK-RC4-SHA";
        TLS_PSK_WITH_3DES_EDE_CBC_SHA                 = "PSK-3DES-EDE-CBC-SHA";
        TLS_PSK_WITH_AES_128_CBC_SHA                  = "PSK-AES128-CBC-SHA";
        TLS_PSK_WITH_AES_256_CBC_SHA                  = "PSK-AES256-CBC-SHA";

        TLS_DHE_PSK_WITH_RC4_128_SHA                  = "DHE-PSK-RC4-SHA";
        TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA             = "DHE-PSK-3DES-EDE-CBC-SHA";
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA              = "DHE-PSK-AES128-CBC-SHA";
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA              = "DHE-PSK-AES256-CBC-SHA";

        TLS_RSA_PSK_WITH_RC4_128_SHA                  = "RSA-PSK-RC4-SHA";
        TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA             = "RSA-PSK-3DES-EDE-CBC-SHA";
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA              = "RSA-PSK-AES128-CBC-SHA";
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA              = "RSA-PSK-AES256-CBC-SHA";

        TLS_PSK_WITH_AES_128_GCM_SHA256               = "PSK-AES128-GCM-SHA256";
        TLS_PSK_WITH_AES_256_GCM_SHA384               = "PSK-AES256-GCM-SHA384";
        TLS_DHE_PSK_WITH_AES_128_GCM_SHA256           = "DHE-PSK-AES128-GCM-SHA256";
        TLS_DHE_PSK_WITH_AES_256_GCM_SHA384           = "DHE-PSK-AES256-GCM-SHA384";
        TLS_RSA_PSK_WITH_AES_128_GCM_SHA256           = "RSA-PSK-AES128-GCM-SHA256";
        TLS_RSA_PSK_WITH_AES_256_GCM_SHA384           = "RSA-PSK-AES256-GCM-SHA384";
        TLS_PSK_WITH_AES_128_CBC_SHA256               = "PSK-AES128-CBC-SHA256";
        TLS_PSK_WITH_AES_256_CBC_SHA384               = "PSK-AES256-CBC-SHA384";
        TLS_PSK_WITH_NULL_SHA256                      = "PSK-NULL-SHA256";
        TLS_PSK_WITH_NULL_SHA384                      = "PSK-NULL-SHA384";
        TLS_DHE_PSK_WITH_AES_128_CBC_SHA256           = "DHE-PSK-AES128-CBC-SHA256";
        TLS_DHE_PSK_WITH_AES_256_CBC_SHA384           = "DHE-PSK-AES256-CBC-SHA384";
        TLS_DHE_PSK_WITH_NULL_SHA256                  = "DHE-PSK-NULL-SHA256";
        TLS_DHE_PSK_WITH_NULL_SHA384                  = "DHE-PSK-NULL-SHA384";
        TLS_RSA_PSK_WITH_AES_128_CBC_SHA256           = "RSA-PSK-AES128-CBC-SHA256";
        TLS_RSA_PSK_WITH_AES_256_CBC_SHA384           = "RSA-PSK-AES256-CBC-SHA384";
        TLS_RSA_PSK_WITH_NULL_SHA256                  = "RSA-PSK-NULL-SHA256";
        TLS_RSA_PSK_WITH_NULL_SHA384                  = "RSA-PSK-NULL-SHA384";

        TLS_ECDHE_PSK_WITH_RC4_128_SHA                = "ECDHE-PSK-RC4-SHA";
        TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA           = "ECDHE-PSK-3DES-EDE-CBC-SHA";
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA            = "ECDHE-PSK-AES128-CBC-SHA";
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA            = "ECDHE-PSK-AES256-CBC-SHA";
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256         = "ECDHE-PSK-AES128-CBC-SHA256";
        TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384         = "ECDHE-PSK-AES256-CBC-SHA384";
        TLS_ECDHE_PSK_WITH_NULL_SHA                   = "ECDHE-PSK-NULL-SHA";
        TLS_ECDHE_PSK_WITH_NULL_SHA256                = "ECDHE-PSK-NULL-SHA256";
        TLS_ECDHE_PSK_WITH_NULL_SHA384                = "ECDHE-PSK-NULL-SHA384";

        TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256          = "PSK-CAMELLIA128-SHA256";
        TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384          = "PSK-CAMELLIA256-SHA384";

        TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256      = "DHE-PSK-CAMELLIA128-SHA256";
        TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384      = "DHE-PSK-CAMELLIA256-SHA384";

        TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256      = "RSA-PSK-CAMELLIA128-SHA256";
        TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384      = "RSA-PSK-CAMELLIA256-SHA384";

        TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256    = "ECDHE-PSK-CAMELLIA128-SHA256";
        TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384    = "ECDHE-PSK-CAMELLIA256-SHA384";

        TLS_PSK_WITH_AES_128_CCM                      = "PSK-AES128-CCM";
        TLS_PSK_WITH_AES_256_CCM                      = "PSK-AES256-CCM";
        TLS_DHE_PSK_WITH_AES_128_CCM                  = "DHE-PSK-AES128-CCM";
        TLS_DHE_PSK_WITH_AES_256_CCM                  = "DHE-PSK-AES256-CCM";
        TLS_PSK_WITH_AES_128_CCM_8                    = "PSK-AES128-CCM8";
        TLS_PSK_WITH_AES_256_CCM_8                    = "PSK-AES256-CCM8";
        TLS_DHE_PSK_WITH_AES_128_CCM_8                = "DHE-PSK-AES128-CCM8";
        TLS_DHE_PSK_WITH_AES_256_CCM_8                = "DHE-PSK-AES256-CCM8";


        -- Export ciphers

        TLS_RSA_EXPORT_WITH_RC4_40_MD5                = "EXP-RC4-MD5";
        TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5            = "EXP-RC2-CBC-MD5";
        TLS_RSA_EXPORT_WITH_DES40_CBC_SHA             = "EXP-DES-CBC-SHA";
        TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA         = "EXP-ADH-DES-CBC-SHA";
        TLS_DH_anon_EXPORT_WITH_RC4_40_MD5            = "EXP-ADH-RC4-MD5";
        TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA         = "EXP-EDH-RSA-DES-CBC-SHA";
        TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA         = "EXP-EDH-DSS-DES-CBC-SHA";
        TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA          = "EXP-DH-DSS-DES-CBC-SHA";
        TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA          = "EXP-DH-RSA-DES-CBC-SHA";


        -- KRB5

        TLS_KRB5_WITH_DES_CBC_SHA                     = "KRB5-DES-CBC-SHA";
        TLS_KRB5_WITH_3DES_EDE_CBC_SHA                = "KRB5-DES-CBC3-SHA";
        TLS_KRB5_WITH_RC4_128_SHA                     = "KRB5-RC4-SHA";
        TLS_KRB5_WITH_IDEA_CBC_SHA                    = "KRB5-IDEA-CBC-SHA";
        TLS_KRB5_WITH_DES_CBC_MD5                     = "KRB5-DES-CBC-MD5";
        TLS_KRB5_WITH_3DES_EDE_CBC_MD5                = "KRB5-DES-CBC3-MD5";
        TLS_KRB5_WITH_RC4_128_MD5                     = "KRB5-RC4-MD5";
        TLS_KRB5_WITH_IDEA_CBC_MD5                    = "KRB5-IDEA-CBC-MD5";
        TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA           = "EXP-KRB5-DES-CBC-SHA";
        TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA           = "EXP-KRB5-RC2-CBC-SHA";
        TLS_KRB5_EXPORT_WITH_RC4_40_SHA               = "EXP-KRB5-RC4-SHA";
        TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5           = "EXP-KRB5-DES-CBC-MD5";
        TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5           = "EXP-KRB5-RC2-CBC-MD5";
        TLS_KRB5_EXPORT_WITH_RC4_40_MD5               = "EXP-KRB5-RC4-MD5";


        -- SRP5

        TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA             = "SRP-3DES-EDE-CBC-SHA";
        TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA         = "SRP-RSA-3DES-EDE-CBC-SHA";
        TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA         = "SRP-DSS-3DES-EDE-CBC-SHA";
        TLS_SRP_SHA_WITH_AES_128_CBC_SHA              = "SRP-AES-128-CBC-SHA";
        TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA          = "SRP-RSA-AES-128-CBC-SHA";
        TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA          = "SRP-DSS-AES-128-CBC-SHA";
        TLS_SRP_SHA_WITH_AES_256_CBC_SHA              = "SRP-AES-256-CBC-SHA";
        TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA          = "SRP-RSA-AES-256-CBC-SHA";
        TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA          = "SRP-DSS-AES-256-CBC-SHA";


        -- CHACHA20+POLY1305

        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = "ECDHE-RSA-CHACHA20-POLY1305";
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = "ECDHE-ECDSA-CHACHA20-POLY1305";
        TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     = "DHE-RSA-CHACHA20-POLY1305";
        TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         = "PSK-CHACHA20-POLY1305";
        TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   = "ECDHE-PSK-CHACHA20-POLY1305";
        TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     = "DHE-PSK-CHACHA20-POLY1305";
        TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256     = "RSA-PSK-CHACHA20-POLY1305";
    }

    -- Banned ciphers from https://http2.github.io/http2-spec/#BadCipherSuites
    local banned_ciphers = {}
    for _, v in ipairs {
        "TLS_NULL_WITH_NULL_NULL";
        "TLS_RSA_WITH_NULL_MD5";
        "TLS_RSA_WITH_NULL_SHA";
        "TLS_RSA_EXPORT_WITH_RC4_40_MD5";
        "TLS_RSA_WITH_RC4_128_MD5";
        "TLS_RSA_WITH_RC4_128_SHA";
        "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5";
        "TLS_RSA_WITH_IDEA_CBC_SHA";
        "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA";
        "TLS_RSA_WITH_DES_CBC_SHA";
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
        "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA";
        "TLS_DH_DSS_WITH_DES_CBC_SHA";
        "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA";
        "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA";
        "TLS_DH_RSA_WITH_DES_CBC_SHA";
        "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA";
        "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA";
        "TLS_DHE_DSS_WITH_DES_CBC_SHA";
        "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA";
        "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA";
        "TLS_DHE_RSA_WITH_DES_CBC_SHA";
        "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA";
        "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5";
        "TLS_DH_anon_WITH_RC4_128_MD5";
        "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA";
        "TLS_DH_anon_WITH_DES_CBC_SHA";
        "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA";
        "TLS_KRB5_WITH_DES_CBC_SHA";
        "TLS_KRB5_WITH_3DES_EDE_CBC_SHA";
        "TLS_KRB5_WITH_RC4_128_SHA";
        "TLS_KRB5_WITH_IDEA_CBC_SHA";
        "TLS_KRB5_WITH_DES_CBC_MD5";
        "TLS_KRB5_WITH_3DES_EDE_CBC_MD5";
        "TLS_KRB5_WITH_RC4_128_MD5";
        "TLS_KRB5_WITH_IDEA_CBC_MD5";
        "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA";
        "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA";
        "TLS_KRB5_EXPORT_WITH_RC4_40_SHA";
        "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5";
        "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5";
        "TLS_KRB5_EXPORT_WITH_RC4_40_MD5";
        "TLS_PSK_WITH_NULL_SHA";
        "TLS_DHE_PSK_WITH_NULL_SHA";
        "TLS_RSA_PSK_WITH_NULL_SHA";
        "TLS_RSA_WITH_AES_128_CBC_SHA";
        "TLS_DH_DSS_WITH_AES_128_CBC_SHA";
        "TLS_DH_RSA_WITH_AES_128_CBC_SHA";
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
        "TLS_DH_anon_WITH_AES_128_CBC_SHA";
        "TLS_RSA_WITH_AES_256_CBC_SHA";
        "TLS_DH_DSS_WITH_AES_256_CBC_SHA";
        "TLS_DH_RSA_WITH_AES_256_CBC_SHA";
        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
        "TLS_DH_anon_WITH_AES_256_CBC_SHA";
        "TLS_RSA_WITH_NULL_SHA256";
        "TLS_RSA_WITH_AES_128_CBC_SHA256";
        "TLS_RSA_WITH_AES_256_CBC_SHA256";
        "TLS_DH_DSS_WITH_AES_128_CBC_SHA256";
        "TLS_DH_RSA_WITH_AES_128_CBC_SHA256";
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256";
        "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA";
        "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA";
        "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA";
        "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA";
        "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA";
        "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA";
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
        "TLS_DH_DSS_WITH_AES_256_CBC_SHA256";
        "TLS_DH_RSA_WITH_AES_256_CBC_SHA256";
        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256";
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
        "TLS_DH_anon_WITH_AES_128_CBC_SHA256";
        "TLS_DH_anon_WITH_AES_256_CBC_SHA256";
        "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA";
        "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA";
        "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA";
        "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA";
        "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA";
        "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA";
        "TLS_PSK_WITH_RC4_128_SHA";
        "TLS_PSK_WITH_3DES_EDE_CBC_SHA";
        "TLS_PSK_WITH_AES_128_CBC_SHA";
        "TLS_PSK_WITH_AES_256_CBC_SHA";
        "TLS_DHE_PSK_WITH_RC4_128_SHA";
        "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA";
        "TLS_DHE_PSK_WITH_AES_128_CBC_SHA";
        "TLS_DHE_PSK_WITH_AES_256_CBC_SHA";
        "TLS_RSA_PSK_WITH_RC4_128_SHA";
        "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA";
        "TLS_RSA_PSK_WITH_AES_128_CBC_SHA";
        "TLS_RSA_PSK_WITH_AES_256_CBC_SHA";
        "TLS_RSA_WITH_SEED_CBC_SHA";
        "TLS_DH_DSS_WITH_SEED_CBC_SHA";
        "TLS_DH_RSA_WITH_SEED_CBC_SHA";
        "TLS_DHE_DSS_WITH_SEED_CBC_SHA";
        "TLS_DHE_RSA_WITH_SEED_CBC_SHA";
        "TLS_DH_anon_WITH_SEED_CBC_SHA";
        "TLS_RSA_WITH_AES_128_GCM_SHA256";
        "TLS_RSA_WITH_AES_256_GCM_SHA384";
        "TLS_DH_RSA_WITH_AES_128_GCM_SHA256";
        "TLS_DH_RSA_WITH_AES_256_GCM_SHA384";
        "TLS_DH_DSS_WITH_AES_128_GCM_SHA256";
        "TLS_DH_DSS_WITH_AES_256_GCM_SHA384";
        "TLS_DH_anon_WITH_AES_128_GCM_SHA256";
        "TLS_DH_anon_WITH_AES_256_GCM_SHA384";
        "TLS_PSK_WITH_AES_128_GCM_SHA256";
        "TLS_PSK_WITH_AES_256_GCM_SHA384";
        "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256";
        "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384";
        "TLS_PSK_WITH_AES_128_CBC_SHA256";
        "TLS_PSK_WITH_AES_256_CBC_SHA384";
        "TLS_PSK_WITH_NULL_SHA256";
        "TLS_PSK_WITH_NULL_SHA384";
        "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256";
        "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384";
        "TLS_DHE_PSK_WITH_NULL_SHA256";
        "TLS_DHE_PSK_WITH_NULL_SHA384";
        "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256";
        "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384";
        "TLS_RSA_PSK_WITH_NULL_SHA256";
        "TLS_RSA_PSK_WITH_NULL_SHA384";
        "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256";
        "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256";
        "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256";
        "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256";
        "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256";
        "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256";
        "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
        "TLS_ECDH_ECDSA_WITH_NULL_SHA";
        "TLS_ECDH_ECDSA_WITH_RC4_128_SHA";
        "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA";
        "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA";
        "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA";
        "TLS_ECDHE_ECDSA_WITH_NULL_SHA";
        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA";
        "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA";
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
        "TLS_ECDH_RSA_WITH_NULL_SHA";
        "TLS_ECDH_RSA_WITH_RC4_128_SHA";
        "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA";
        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA";
        "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA";
        "TLS_ECDHE_RSA_WITH_NULL_SHA";
        "TLS_ECDHE_RSA_WITH_RC4_128_SHA";
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA";
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
        "TLS_ECDH_anon_WITH_NULL_SHA";
        "TLS_ECDH_anon_WITH_RC4_128_SHA";
        "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA";
        "TLS_ECDH_anon_WITH_AES_128_CBC_SHA";
        "TLS_ECDH_anon_WITH_AES_256_CBC_SHA";
        "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA";
        "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA";
        "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA";
        "TLS_SRP_SHA_WITH_AES_128_CBC_SHA";
        "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA";
        "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA";
        "TLS_SRP_SHA_WITH_AES_256_CBC_SHA";
        "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA";
        "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA";
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
        "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256";
        "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384";
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256";
        "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384";
        "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256";
        "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384";
        "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256";
        "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384";
        "TLS_ECDHE_PSK_WITH_RC4_128_SHA";
        "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA";
        "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA";
        "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA";
        "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256";
        "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384";
        "TLS_ECDHE_PSK_WITH_NULL_SHA";
        "TLS_ECDHE_PSK_WITH_NULL_SHA256";
        "TLS_ECDHE_PSK_WITH_NULL_SHA384";
        "TLS_RSA_WITH_ARIA_128_CBC_SHA256";
        "TLS_RSA_WITH_ARIA_256_CBC_SHA384";
        "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256";
        "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384";
        "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256";
        "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384";
        "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256";
        "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384";
        "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256";
        "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384";
        "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256";
        "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384";
        "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256";
        "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384";
        "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256";
        "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384";
        "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256";
        "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384";
        "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256";
        "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384";
        "TLS_RSA_WITH_ARIA_128_GCM_SHA256";
        "TLS_RSA_WITH_ARIA_256_GCM_SHA384";
        "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256";
        "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384";
        "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256";
        "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384";
        "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256";
        "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384";
        "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256";
        "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384";
        "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256";
        "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384";
        "TLS_PSK_WITH_ARIA_128_CBC_SHA256";
        "TLS_PSK_WITH_ARIA_256_CBC_SHA384";
        "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256";
        "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384";
        "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256";
        "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384";
        "TLS_PSK_WITH_ARIA_128_GCM_SHA256";
        "TLS_PSK_WITH_ARIA_256_GCM_SHA384";
        "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256";
        "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384";
        "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256";
        "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384";
        "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
        "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384";
        "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384";
        "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384";
        "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256";
        "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384";
        "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256";
        "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384";
        "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256";
        "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384";
        "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256";
        "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384";
        "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256";
        "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384";
        "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256";
        "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384";
        "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256";
        "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384";
        "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256";
        "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384";
        "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384";
        "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
        "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384";
        "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256";
        "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384";
        "TLS_RSA_WITH_AES_128_CCM";
        "TLS_RSA_WITH_AES_256_CCM";
        "TLS_RSA_WITH_AES_128_CCM_8";
        "TLS_RSA_WITH_AES_256_CCM_8";
        "TLS_PSK_WITH_AES_128_CCM";
        "TLS_PSK_WITH_AES_256_CCM";
        "TLS_PSK_WITH_AES_128_CCM_8";
        "TLS_PSK_WITH_AES_256_CCM_8";
    } do
        local openssl_cipher_name = spec_to_openssl[v]
        if openssl_cipher_name then
            banned_ciphers[openssl_cipher_name] = true
        end
    end

    local default_tls_options = openssl.ssl.context.OP_NO_COMPRESSION
        + openssl.ssl.context.OP_SINGLE_ECDH_USE
        + openssl.ssl.context.OP_NO_SSLv2
        + openssl.ssl.context.OP_NO_SSLv3

    function https.client_context()
        local ctx = openssl.ssl.context.new("TLS", false)
        ctx:setCipherList(intermediate_cipher_list)
        ctx:setOptions(default_tls_options)
        ctx:setEphemeralKey(openssl.pkey.new{ type = "EC", curve = "prime256v1" })
        local store = ctx:getStore()
        store:addDefaults()
        ctx:setVerify(openssl.ssl.context.VERIFY_PEER)
        return ctx
    end

    function https.server_context()
        local ctx = openssl.ssl.context.new("TLS", true)
        ctx:setCipherList(intermediate_cipher_list)
        ctx:setOptions(default_tls_options)
        ctx:setEphemeralKey(openssl.pkey.new{ type = "EC", curve = "prime256v1" })
        return ctx
    end

end

-- Utility modules
local util = {}
do

    -- checks if list has value
    function util.has(list, val)
        if list then for i=1, #list do if list[i] == val then return true end end end
        return false
    end

    function util.has_any(list, val, ...)
        if util.has(list, val) then return true elseif (...) then return util.has(list, ...) else return false end
    end

    -- Encodes a character as a percent encoded string
    function util.char_to_pchar(c)
        return string.format("%%%02X", c:byte(1,1))
    end

    -- encodeURI replaces all characters except the following with the appropriate UTF-8 escape sequences:
    -- ; , / ? : @ & = + $
    -- alphabetic, decimal digits, - _ . ! ~ * ' ( )
    -- #
    function util.encodeURI(str)
        return string.gsub(str, "[^%;%,%/%?%:%@%&%=%+%$%w%-%_%.%!%~%*%'%(%)%#]", util.char_to_pchar)
    end

    -- encodeURIComponent escapes all characters except the following: alphabetic, decimal digits, - _ . ! ~ * ' ( )
    function util.encodeURIComponent(str)
        return string.gsub(str, "[^%w%-_%.%!%~%*%'%(%)]", util.char_to_pchar)
    end

    -- decodeURI unescapes url encoded characters
    -- excluding characters that are special in urls
    local decodeURI do
        local decodeURI_blacklist = {}
        for char in ("#$&+,/:;=?@"):gmatch(".") do
            decodeURI_blacklist[string.byte(char)] = true
        end
        function util.decodeURI_helper(str)
            local x = tonumber(str, 16)
            if not decodeURI_blacklist[x] then
                return string.char(x)
            end
            -- return nothing; gsub will not perform the replacement
        end
        function decodeURI(str)
            return (str:gsub("%%(%x%x)", decodeURI_helper))
        end
    end
    util.decodeURI = decodeURI 

    -- Converts a hex string to a character
    function util.pchar_to_char(str)
        return string.char(tonumber(str, 16))
    end

    -- decodeURIComponent unescapes *all* url encoded characters
    function util.decodeURIComponent(str)
        return (str:gsub("%%(%x%x)", pchar_to_char))
    end

    -- An iterator over query segments (delimited by "&") as key/value pairs
    -- if a query segment has no '=', the value will be `nil`
    function util.query_args(str)
        local iter, state, first = str:gmatch("([^=&]+)(=?)([^&]*)&?")
        return function(state, last) -- luacheck: ignore 431
            local name, equals, value = iter(state, last)
            if name == nil then return nil end
            name = util.decodeURIComponent(name)
            if equals == "" then
                value = nil
            else
                value = util.decodeURIComponent(value)
            end
            return name, value
        end, state, first
    end

    -- Converts a dictionary (string keys, string values) to an encoded query string
    function util.dict_to_query(form)
        local r, i = {}, 0
        for name, value in pairs(form) do
            i = i + 1
            r[i] = util.encodeURIComponent(name).."="..util.encodeURIComponent(value)
        end
        return table.concat(r, "&", 1, i)
    end

    -- Resolves a relative path
    function util.resolve_relative_path(orig_path, relative_path)
        local t, i = {}, 0

        local is_abs
        if relative_path:sub(1,1) == "/" then
            -- "relative" argument is actually absolute. ignore orig_path argument
            is_abs = true
        else
            is_abs = orig_path:sub(1,1) == "/"
            -- this will skip empty path components due to +
            -- the / on the end ignores trailing component
            for segment in orig_path:gmatch("([^/]+)/") do
                i = i + 1
                t[i] = segment
            end
        end

        for segment in relative_path:gmatch("([^/]+)") do
            if segment == ".." then
                -- if we're at the root, do nothing
                if i > 0 then
                    -- discard a component
                    i = i - 1
                end
            elseif segment ~= "." then
                i = i + 1
                t[i] = segment
            end
        end

        -- Make sure leading slash is kept
        local s
        if is_abs then
            if i == 0 then return "/" end
            t[0] = ""
            s = 0
        else
            s = 1
        end
        -- Make sure trailing slash is kept
        if relative_path:sub(-1, -1) == "/" then
            i = i + 1
            t[i] = ""
        end
        return table.concat(t, "/", s, i)
    end

    local safe_methods = {
        -- RFC 7231 Section 4.2.1:
        -- Of the request methods defined by this specification, the GET, HEAD,
        -- OPTIONS, and TRACE methods are defined to be safe.
        GET = true;
        HEAD = true;
        OPTIONS = true;
        TRACE = true;
    }
    function util.is_safe_method(method)
        return safe_methods[method] or false
    end

    function util.is_ip(str)
        return #{str:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")} == 4
    end

    local scheme_to_port = {
        http = 80;
        ws = 80;
        https = 443;
        wss = 443;
    }

    -- Splits a :authority header (same as Host) into host and port
    function util.split_authority(authority, scheme)
        local host, port
        local h, p = authority:match("^[ \t]*(.-):(%d+)[ \t]*$")
        if p then
            authority = h
            port = tonumber(p, 10)
        else -- when port missing from host header, it defaults to the default for that scheme
            port = scheme_to_port[scheme]
            if port == nil then
                return nil, "unknown scheme"
            end
        end
        host = authority
        return host, port
    end

    -- Reverse of `split_authority`: converts a host, port and scheme
    -- into a string suitable for an :authority header.
    function util.to_authority(host, port, scheme)
        local authority = host
        local default_port = scheme_to_port[scheme]
        if default_port == port then
            port = nil
        end
        if port then
            authority = string.format("%s:%d", authority, port)
        end
        return authority
    end

    -- HTTP prefered date format
    -- See RFC 7231 section 7.1.1.1
    function util.imf_date(time)
        return os.date("!%a, %d %b %Y %H:%M:%S GMT", time)
    end

    local function handle_resume(co, ok, ...)
        if not ok then
            return false, ...
        elseif coroutine.status(co) == "dead" then
            return true, ...
        end
        return handle_resume(co, coroutine.resume(co, coroutine.yield(...)))
    end
    util.yieldable_pcall = function(func, ...)
        if type(func) ~= "function" or debug.getinfo(func, "S").what == "C" then
            local C_func = func
            -- Can't give C functions to coroutine.create
            func = function(...) return C_func(...) end
        end
        local co = coroutine.create(func)
        return handle_resume(co, coroutine.resume(co, ...))
    end
end

-- HTTP client
local client = {}
do
    local default_ctx = https.client_context()

    function client.negotiate(s, options, timeout)
        --s:onerror(onerror)
        local tls = options.tls
        local version = options.version
        if tls then
            local ctx = options.ctx or default_ctx
            local ssl = openssl.ssl.new(ctx)
            local host = options.host
            local host_is_ip = host and util.is_ip(host)
            local sendname = options.sendname
            if sendname == nil and not host_is_ip and host then
                sendname = host
            end
            if sendname then -- false indicates no sendname wanted
                ssl:setHostName(sendname)
            end
            if host and https.has_hostname_validation then
                local params = openssl.x509.verify_param.new()
                if host_is_ip then
                    params:setIP(host)
                else
                    params:setHost(host)
                end
                -- Allow user defined params to override
                local old = ssl:getParam()
                old:inherit(params)
                ssl:setParam(old)
            end
            local ok, err, errno = s:starttls(ssl, timeout)
            if not ok then
                return nil, err, errno
            end
        end
        version = version or 1.1 
        return conn.new(s, "client", version)
    end

    function client.connect(options, timeout)
        local bind = options.bind
        if bind ~= nil then
            assert(type(bind) == "string")
            local bind_address, bind_port = bind:match("^(.-):(%d+)$")
            if bind_address then
                bind_port = tonumber(bind_port, 10)
            else
                bind_address = bind
            end
            bind = {
                address = bind_address;
                port = bind_port;
            }
        end
        local s, err, errno = ca.fileresult(cs.connect {
            family = options.family;
            host = options.host;
            port = options.port;
            path = options.path;
            bind = bind;
            sendname = false;
            nodelay = true;
        })
        if s == nil then
            return nil, err, errno
        end
        return client.negotiate(s, options, timeout)
    end
end

-- HTTP request
local request = {}
do
    local request_methods = {
        is_top_level = true;
        expect_100_timeout = 1;
        follow_redirects = true;
        max_redirects = 5;
        post301 = false;
        post302 = false;
    }

    local request_mt = {
        __name = "http.request";
        __index = request_methods;
    }

    function request.parse_uri(url)
        local scheme, host, hostname, port, path = url:match("^(https?:)//(([^/:]+):?([0-9]*))(/?.*)$")
        port = port~='' and tonumber(port) or (scheme=='https:' and 443 or 80)
        return {scheme=scheme, host=host, port=port, path=path}
    end
        

    function request.new_from_uri(uri, headers)
        local uri_t = request.parse_uri(uri)
        local scheme = uri_t.scheme 
        local host = uri_t.host 
        local port = uri_t.port
        assert(scheme == "https:" or scheme == "http:", "scheme not valid")
        assert(host, "host is not valid")
        local is_connect -- CONNECT requests are a bit special, see http2 spec section 8.3
        if headers == nil then
            headers = headers_new()
            headers:append(":method", "GET")
            is_connect = false
        else
            is_connect = headers:get(":method") == "CONNECT"
        end
        if is_connect then
            assert(uri_t.path == nil or uri_t.path == "", "CONNECT requests cannot have a path")
            assert(uri_t.query == nil, "CONNECT requests cannot have a query")
            assert(headers:has(":authority"), ":authority required for CONNECT requests")
        else
            headers:upsert(":authority", util.to_authority(host, port, scheme))
            local path = uri_t.path
            if path == nil or path == "" then
                path = "/"
            end
            if uri_t.query then
                path = path .. "?" .. uri_t.query
            end
            headers:upsert(":path", path)
            headers:upsert(":scheme", scheme)
        end
        if uri_t.userinfo then
            local field
            if is_connect then
                field = "proxy-authorization"
            else
                field = "authorization"
            end
            local userinfo = util.decodeURIComponent(uri_t.userinfo) -- XXX: this doesn't seem right, but it's the same behaviour as curl
            headers:upsert(field, "basic " .. basexx.to_base64(userinfo), true)
        end
        if not headers:has("user-agent") then headers:append("user-agent", 'unknown (null)') end
        return setmetatable({
            host = host;
            port = port;
            tls = (scheme == "https:");
            headers = headers;
            body = nil;
        }, request_mt)
    end

    function request.new_connect(uri, connect_authority)
        local headers = headers_new()
        headers:append(":authority", connect_authority)
        headers:append(":method", "CONNECT")
        return new_from_uri(uri, headers)
    end

    function request_methods:clone()
        return setmetatable({
            host = self.host;
            port = self.port;
            bind = self.bind;
            tls = self.tls;
            ctx = self.ctx;
            sendname = self.sendname;
            version = self.version;
            proxy = self.proxy;

            headers = self.headers:clone();
            body = self.body;

            is_top_level = rawget(self, "is_top_level");
            expect_100_timeout = rawget(self, "expect_100_timeout");
            follow_redirects = rawget(self, "follow_redirects");
            max_redirects = rawget(self, "max_redirects");
            post301 = rawget(self, "post301");
            post302 = rawget(self, "post302");
        }, request_mt)
    end

    function request_methods:to_uri(with_userinfo)
        local scheme = self.headers:get(":scheme")
        local method = self.headers:get(":method")
        local path
        if scheme == nil then
            scheme = self.tls and "https:" or "http:"
        end
        local authority
        local authorization_field
        if method == "CONNECT" then
            authorization_field = "proxy-authorization"
            path = ""
        else
            path = self.headers:get(":path")
            local path_t
            if method == "OPTIONS" and path == "*" then
                path = ""
            else
                assert(path_t, "path not a valid uri reference")
            end
            if path_t and path_t.host then
                -- path was a full URI. This is used for proxied requests.
                scheme = path_t.scheme or scheme
                path = path_t.path or ""
                if path_t.query then
                    path = path .. "?" .. path_t.query
                end
                authority = util.to_authority(path_t.host, path_t.port, scheme)
            else
                authority = self.headers:get(":authority")
                -- TODO: validate authority can fit in a url
            end
            authorization_field = "authorization"
        end
        if authority == nil then
            authority = util.to_authority(self.host, self.port, scheme)
        end
        if with_userinfo and self.headers:has(authorization_field) then
            local authorization = self.headers:get(authorization_field)
            local auth_type, userinfo = authorization:match("^%s*(%S+)%s+(%S+)%s*$")
            if auth_type and auth_type:lower() == "basic" then
                userinfo = basexx.from_base64(userinfo)
                userinfo = util.encodeURI(userinfo)
                authority = userinfo .. "@" .. authority
            else
                error("authorization cannot be converted to uri")
            end
        end
        return scheme .. "//" .. authority .. path
    end

    function request_methods:handle_redirect(orig_headers)
        local max_redirects = self.max_redirects
        if max_redirects <= 0 then
            return nil, "maximum redirects exceeded", ce.ELOOP
        end
        local location = orig_headers:get("location")
        if not location then
            return nil, "missing location header for redirect", ce.EINVAL
        end
        local uri_t = location 
        local new_req = self:clone()
        new_req.max_redirects = max_redirects - 1
        local method = new_req.headers:get(":method")
        local is_connect = method == "CONNECT"
        local new_scheme = uri_t.scheme
        if new_scheme then
            if not is_connect then
                new_req.headers:upsert(":scheme", new_scheme)
            end
            if new_scheme == "https" or new_scheme == "wss" then
                new_req.tls = true
            elseif new_scheme == "http" or new_scheme == "ws" then
                new_req.tls = false
            else
                return nil, "unknown scheme", ce.EINVAL
            end
        else
            if not is_connect then
                new_scheme = new_req.headers:get(":scheme")
            end
            if new_scheme == nil then
                new_scheme = self.tls and "https:" or "http:"
            end
        end
        local orig_target
        local target_authority
        if not is_connect then
            orig_target = self.headers:get(":path")
            if orig_target and orig_target.host then
                -- was originally a proxied request
                local new_authority
                if uri_t.host then -- we have a new host
                    new_authority = util.to_authority(uri_t.host, uri_t.port, new_scheme)
                    new_req.headers:upsert(":authority", new_authority)
                else
                    new_authority = self.headers:get(":authority")
                end
                if new_authority == nil then
                    new_authority = util.to_authority(self.host, self.port, new_scheme)
                end
                -- prefix for new target
                target_authority = new_scheme .. "://" .. new_authority
            end
        end
        if target_authority == nil and uri_t.host then
            -- we have a new host and it wasn't placed into :authority
            new_req.host = uri_t.host
            if not is_connect then
                new_req.headers:upsert(":authority", util.to_authority(uri_t.host, uri_t.port, new_scheme))
            end
            new_req.port = uri_t.port or util.scheme_to_port[new_scheme]
            new_req.sendname = nil
        end -- otherwise same host as original request; don't need change anything
        if is_connect then
            if uri_t.path ~= nil and uri_t.path ~= "" then
                return nil, "CONNECT requests cannot have a path", ce.EINVAL
            elseif uri_t.query ~= nil then
                return nil, "CONNECT requests cannot have a query", ce.EINVAL
            end
        else
            local new_path
            if uri_t.path == nil or uri_t.path == "" then
                new_path = "/"
            else
                new_path = uri_t.path
                if new_path:sub(1, 1) ~= "/" then -- relative path
                    if not orig_target then
                        return nil, "base path not valid for relative redirect", ce.EINVAL
                    end
                    local orig_path = orig_target.path or "/"
                    new_path = util.resolve_relative_path(orig_path, new_path)
                end
            end
            if uri_t.query then
                new_path = new_path .. "?" .. uri_t.query
            end
            if target_authority then
                new_path = target_authority .. new_path
            end
            new_req.headers:upsert(":path", new_path)
        end
        if uri_t.userinfo then
            local field
            if is_connect then
                field = "proxy-authorization"
            else
                field = "authorization"
            end
            new_req.headers:upsert(field, "basic " .. basexx.to_base64(uri_t.userinfo), true)
        end
        if not new_req.tls and self.tls then
            --[[ RFC 7231 5.5.2: A user agent MUST NOT send a Referer header field in an
            unsecured HTTP request if the referring page was received with a secure protocol.]]
            new_req.headers:delete("referer")
        else
            new_req.headers:upsert("referer", self:to_uri(false))
        end
        -- Change POST requests to a body-less GET on redirect?
        local orig_status = orig_headers:get(":status")
        if (orig_status == "303"
            or (orig_status == "301" and not self.post301)
            or (orig_status == "302" and not self.post302)
            ) and method == "POST"
        then
            new_req.headers:upsert(":method", "GET")
            -- Remove headers that don't make sense without a body
            -- Headers that require a body
            new_req.headers:delete("transfer-encoding")
            new_req.headers:delete("content-length")
            -- Representation Metadata from RFC 7231 Section 3.1
            new_req.headers:delete("content-encoding")
            new_req.headers:delete("content-language")
            new_req.headers:delete("content-location")
            new_req.headers:delete("content-type")
            -- Other...
            local expect = new_req.headers:get("expect")
            if expect and expect:lower() == "100-continue" then
                new_req.headers:delete("expect")
            end
            new_req.body = nil
        end
        return new_req
    end

    function request_methods:set_body(body)
        self.body = body
        local length
        if type(self.body) == "string" then
            length = #body
        end
        if length then
            self.headers:upsert("content-length", string.format("%d", #body))
        end
        if not length or length > 1024 then
            self.headers:append("expect", "100-continue")
        end
        return true
    end

    function request.non_final_status(status)
        return status:sub(1, 1) == "1" and status ~= "101"
    end

    function request_methods:go(timeout)
        local deadline = timeout and (cqueues.monotime()+timeout)

        local cloned_headers = false -- only clone headers when we need to
        local request_headers = self.headers
        local host = self.host
        local port = self.port
        local tls = self.tls

        -- RFC 6797 Section 8.3
        --if not tls and self.hsts and self.hsts:check(host) then
            --tls = true

            --if request_headers:get(":scheme") == "http" then
                ---- The UA MUST replace the URI scheme with "https"
                --if not cloned_headers then
                    --request_headers = request_headers:clone()
                    --cloned_headers = true
                --end
                --request_headers:upsert(":scheme", "https")
            --end

            ---- if the URI contains an explicit port component of "80", then
            ---- the UA MUST convert the port component to be "443", or
            ---- if the URI contains an explicit port component that is not
            ---- equal to "80", the port component value MUST be preserved
            --if port == 80 then
                --port = 443
            --end
        --end

        local connection

        if not connection then
            local err, errno
            connection, err, errno = client.connect({
                host = host;
                port = port;
                bind = self.bind;
                tls = tls;
                ctx = self.ctx;
                sendname = self.sendname;
                version = self.version;
                h2_settings = default_h2_settings;
            }, deadline and deadline-cqueues.monotime())
            if connection == nil then
                return nil, err, errno
            end
            -- Close the connection (and free resources) when done
            connection:onidle(connection.close)
        end

        local stream do
            local err, errno
            stream, err, errno = connection:new_stream()
            if stream == nil then
                return nil, err, errno
            end
        end

        local body = self.body
        do -- Write outgoing headers
            local ok, err, errno = stream:write_headers(request_headers, body == nil, deadline and deadline-cqueues.monotime())
            if not ok then
                stream:shutdown()
                return nil, err, errno
            end
        end

        local headers
        if body then
            local expect = request_headers:get("expect")
            if expect and expect:lower() == "100-continue" then
                -- Try to wait for 100-continue before proceeding
                if deadline then
                    local err, errno
                    headers, err, errno = stream:get_headers(math.min(self.expect_100_timeout, deadline-cqueues.monotime()))
                    if headers == nil and (errno ~= ce.ETIMEDOUT or cqueues.monotime() > deadline) then
                        stream:shutdown()
                        if err == nil then
                            return nil, ce.strerror(ce.EPIPE), ce.EPIPE
                        end
                        return nil, err, errno
                    end
                else
                    local err, errno
                    headers, err, errno = stream:get_headers(self.expect_100_timeout)
                    if headers == nil and errno ~= ce.ETIMEDOUT then
                        stream:shutdown()
                        if err == nil then
                            return nil, ce.strerror(ce.EPIPE), ce.EPIPE
                        end
                        return nil, err, errno
                    end
                end
                if headers and headers:get(":status") ~= "100" then
                    -- Don't send body
                    body = nil
                end
            end
            if body then
                local ok, err, errno
                if type(body) == "string" then
                    ok, err, errno = stream:write_body_from_string(body, deadline and deadline-cqueues.monotime())
                elseif io.type(body) == "file" then
                    ok, err, errno = body:seek("set")
                    if ok then
                        ok, err, errno = stream:write_body_from_file(body, deadline and deadline-cqueues.monotime())
                    end
                elseif type(body) == "function" then
                    -- call function to get body segments
                    while true do
                        local chunk = body()
                        if chunk then
                            ok, err, errno = stream:write_chunk(chunk, false, deadline and deadline-cqueues.monotime())
                            if not ok then
                                break
                            end
                        else
                            ok, err, errno = stream:write_chunk("", true, deadline and deadline-cqueues.monotime())
                            break
                        end
                    end
                end
                if not ok then
                    stream:shutdown()
                    return nil, err, errno
                end
            end
        end
        if not headers or non_final_status(headers:get(":status")) then
            -- Skip through 1xx informational headers.
            -- From RFC 7231 Section 6.2: "A user agent MAY ignore unexpected 1xx responses"
            repeat
                local err, errno
                headers, err, errno = stream:get_headers(deadline and (deadline-cqueues.monotime()))
                if headers == nil then
                    stream:shutdown()
                    if err == nil then
                        return nil, ce.strerror(ce.EPIPE), ce.EPIPE
                    end
                    return nil, err, errno
                end
            until not request.non_final_status(headers:get(":status"))
        end

        if self.follow_redirects and headers:get(":status"):sub(1,1) == "3" then
            stream:shutdown()
            local new_req, err2, errno2 = self:handle_redirect(headers)
            if not new_req then
                return nil, err2, errno2
            end
            return new_req:go(deadline and (deadline-cqueues.monotime()))
        end

        return headers, stream
    end
end

-- HTTP server
local server = {} 
do
    server.hang_timeout = 0.03

    -- Sense for TLS or SSL client hello
    -- returns `true`, `false` or `nil, err`
    local function is_tls_client_hello(socket, timeout)
        -- reading for 6 bytes should be safe, as no HTTP version
        -- has a valid client request shorter than 6 bytes
        local first_bytes, err, errno = socket:xread(6, timeout)
        if first_bytes == nil then
            return nil, err or ce.EPIPE, errno
        end
        local use_tls = not not (
            first_bytes:match("^[\21\22]\3[\1\2\3]..\1") or -- TLS
            first_bytes:match("^[\128-\255][\9-\255]\1") -- SSLv2
        )
        local ok
        ok, errno = socket:unget(first_bytes)
        if not ok then
            return nil, conn.onerror(socket, "unget", errno, 2)
        end
        return use_tls
    end

    -- Wrap a bare cqueues socket in an HTTP connection of a suitable version
    -- Starts TLS if necessary
    -- this function *should never throw*
    local function wrap_socket(self, socket, timeout)
        local deadline = timeout and cqueues.monotime()+timeout
        socket:setmode("b", "b")
        socket:onerror(conn.onerror)
        local version = self.version
        local use_tls = self.tls
        if use_tls == nil then
            local err, errno
            use_tls, err, errno = is_tls_client_hello(socket, deadline and (deadline-cqueues.monotime()))
            if use_tls == nil then
                return nil, err, errno
            end
        end
        if use_tls then
            local ok, err, errno = socket:starttls(self.ctx, deadline and (deadline-cqueues.monotime()))
            if not ok then
                return nil, err, errno
            end
            local ssl = assert(socket:checktls())
        end
        -- Still not sure if incoming connection is an HTTP1 or HTTP2 connection
        -- Need to sniff for the h2 connection preface to find out for sure
        version = version or 1.1
        local c = conn.new(socket, "server", version)
        return c
    end

    local function server_loop(self)
        while self.socket do
            if self.paused then
                cqueues.poll(self.pause_cond)
            elseif self.n_connections >= self.max_concurrent then
                cqueues.poll(self.connection_done)
            else
                local socket, accept_errno = self.socket:accept({nodelay = true;}, 0)
                if socket == nil then
                    if accept_errno == ce.ETIMEDOUT then
                        -- Yield this thread until a client arrives
                        cqueues.poll(self.socket, self.pause_cond)
                    elseif accept_errno == ce.EMFILE then
                        -- Wait for another request to finish
                        if cqueues.poll(self.connection_done, server.hang_timeout) == server.hang_timeout then
                            -- If we're stuck waiting, run a garbage collection sweep
                            -- This can prevent a hang
                            collectgarbage()
                        end
                    else
                        self:onerror()(self, self, "accept", ce.strerror(accept_errno), accept_errno)
                    end
                else
                    self:add_socket(socket)
                end
            end
        end
    end

    local function handle_socket(self, socket)
        local error_operation, error_context
        local c, err, errno = wrap_socket(self, socket, self.connection_setup_timeout)
        if not c then
            socket:close()
            if err ~= ce.EPIPE -- client closed connection
                and errno ~= ce.ETIMEDOUT -- an operation timed out
                and errno ~= ce.ECONNRESET then
                error_operation = "wrap"
                error_context = socket
            end
        else
            local cond = cc.new()
            local idle = true
            local deadline
            c:onidle(function()
                idle = true
                deadline = self.intra_stream_timeout + cqueues.monotime()
                cond:signal(1)
            end)
            while true do
                local timeout = deadline and deadline-cqueues.monotime() or self.intra_stream_timeout
                local stream
                stream = c:get_next_incoming_stream(timeout)
                if stream == nil then
                    if (err ~= nil -- client closed connection
                        and errno ~= ce.ECONNRESET
                        and errno ~= ce.ENOTCONN
                        and errno ~= ce.ETIMEDOUT) then
                        error_operation = "get_next_incoming_stream"
                        error_context = c
                        break
                    elseif errno ~= ce.ETIMEDOUT or not idle or (deadline and deadline <= cqueues.monotime()) then -- want to go around loop again if deadline not hit
                        break
                    end
                else
                    idle = false
                    deadline = nil
                    self:add_stream(stream)
                end
            end
            -- wait for streams to complete
            if not idle then
                cond:wait()
            end
            c:close()
        end
        self.n_connections = self.n_connections - 1
        self.connection_done:signal(1)
        if error_operation then
            self:onerror()(self, error_context, error_operation, err, errno)
        end
    end

    local function handle_stream(self, stream)
        local ok, err = util.yieldable_pcall(self.onstream, self, stream)
        stream:shutdown()
        if not ok then
            self:onerror()(self, stream, "onstream", err)
        end
    end

    -- create a new self signed cert
    local function new_ctx(host, version)
        local ctx = https.server_context()
        local crt = openssl.x509.new()
        crt:setVersion(3)
        -- serial needs to be unique or browsers will show uninformative error messages
        crt:setSerial(openssl.bignum.fromBinary(openssl.rand.bytes(16)))
        -- use the host we're listening on as canonical name
        local dn = openssl.x509.name.new()
        dn:add("CN", host)
        crt:setSubject(dn)
        crt:setIssuer(dn) -- should match subject for a self-signed
        local alt = openssl.x509.altname.new()
        alt:add("DNS", host)
        crt:setSubjectAlt(alt)
        -- lasts for 10 years
        crt:setLifetime(os.time(), os.time()+86400*3650)
        -- can't be used as a CA
        crt:setBasicConstraints{CA=false}
        crt:setBasicConstraintsCritical(true)
        -- generate a new private/public key pair
        local key = openssl.pkey.new({bits=2048})
        crt:setPublicKey(key)
        crt:sign(key)
        assert(ctx:setPrivateKey(key))
        assert(ctx:setCertificate(crt))
        return ctx
    end

    local server_methods = {
        version = nil;
        max_concurrent = math.huge;
        connection_setup_timeout = 10;
        intra_stream_timeout = 10;
    }
    local server_mt = {
        __name = "http.server";
        __index = server_methods;
        __tostring = function() return "http.server" end,
    }

    --[[ Creates a new server object

    Takes a table of options:
      - `.cq` (optional): A cqueues controller to use
      - `.socket` (optional): A cqueues socket object to accept() from
      - `.onstream`: function to call back for each stream read
      - `.onerror`: function that will be called when an error occurs (default: throw an error)
      - `.tls`: `nil`: allow both tls and non-tls connections
      -         `true`: allows tls connections only
      -         `false`: allows non-tls connections only
      - `.ctx`: an `openssl.ssl.context` object to use for tls connections
      - `       `nil`: a self-signed context will be generated
      - `.version`: the http version to allow to connect (default: any)
      - `.max_concurrent`: Maximum number of connections to allow live at a time (default: infinity)
      - `.connection_setup_timeout`: Timeout (in seconds) to wait for client to send first bytes and/or complete TLS handshake (default: 10)
      - `.intra_stream_timeout`: Timeout (in seoncds) to wait between start of client streams (default: 10)
    ]]
    function server.new(tbl)
        local cq = tbl.cq
        if cq == nil then
            cq = cqueues.new()
        else
            assert(cqueues.type(cq) == "controller", "optional cq field should be a cqueue controller")
        end
        local socket = tbl.socket
        if socket ~= nil then
            assert(cs.type(socket), "optional socket field should be a cqueues socket")
        end
        local onstream = assert(tbl.onstream, "missing 'onstream'")
        if tbl.ctx == nil and tbl.tls ~= false then
            error("OpenSSL context required if .tls isn't false")
        end

        local self = setmetatable({
            cq = cq;
            socket = socket;
            onstream = onstream;
            onerror_ = tbl.onerror;
            tls = tbl.tls;
            ctx = tbl.ctx;
            version = tbl.version;
            max_concurrent = tbl.max_concurrent;
            n_connections = 0;
            pause_cond = cc.new();
            paused = false;
            connection_done = cc.new(); -- signalled when connection has been closed
            connection_setup_timeout = tbl.connection_setup_timeout;
            intra_stream_timeout = tbl.intra_stream_timeout;
        }, server_mt)

        if socket then
            -- Return errors rather than throwing
            socket:onerror(function(socket, op, why, lvl) -- luacheck: ignore 431 212
                return why
            end)
            cq:wrap(server_loop, self)
        end

        return self
    end

    --[[
    Extra options:
      - `.family`: protocol family
      - `.host`: address to bind to (required if not `.path`)
      - `.port`: port to bind to (optional if tls isn't `nil`, in which case defaults to 80 for `.tls == false` or 443 if `.tls == true`)
      - `.path`: path to UNIX socket (required if not `.host`)
      - `.mode`: fchmod or chmod socket after creating UNIX domain socket
      - `.mask`: set and restore umask when binding UNIX domain socket
      - `.unlink`: unlink socket path before binding?
      - `.reuseaddr`: turn on SO_REUSEADDR flag?
      - `.reuseport`: turn on SO_REUSEPORT flag?
    ]]
    function server.listen(tbl)
        local tls = tbl.tls
        local host = tbl.host
        local path = tbl.path
        assert(host or path, "need host or path")
        local port = tbl.port
        if host and port == nil then
            if tls == true then
                port = "443"
            elseif tls == false then
                port = "80"
            else
                error("need port")
            end
        end
        local ctx = tbl.ctx
        if ctx == nil and tls ~= false then
            if host then
                ctx = new_ctx(host, tbl.version)
            else
                error("Custom OpenSSL context required when using a UNIX domain socket")
            end
        end
        local s, err, errno = ca.fileresult(cs.listen {
            family = tbl.family;
            host = host;
            port = port;
            path = path;
            mode = tbl.mode;
            mask = tbl.mask;
            unlink = tbl.unlink;
            reuseaddr = tbl.reuseaddr;
            reuseport = tbl.reuseport;
        })
        if not s then
            return nil, err, errno
        end
        return server.new {
            cq = tbl.cq;
            socket = s;
            onstream = tbl.onstream;
            onerror = tbl.onerror;
            tls = tls;
            ctx = ctx;
            version = tbl.version;
            max_concurrent = tbl.max_concurrent;
            connection_setup_timeout = tbl.connection_setup_timeout;
            intra_stream_timeout = tbl.intra_stream_timeout;
        }
    end

    function server_methods:onerror_(context, op, err, errno) -- luacheck: ignore 212
        local msg = op
        if err then
            msg = msg .. ": " .. tostring(err)
        end
        error(msg, 2)
    end

    function server_methods:onerror(...)
        local old_handler = self.onerror_
        if select("#", ...) > 0 then
            self.onerror_ = ...
        end
        return old_handler
    end

    -- Actually wait for and *do* the binding
    -- Don't *need* to call this, as if not it will be done lazily
    function server_methods:listen(timeout)
        if self.socket then
            local ok, err, errno = ca.fileresult(self.socket:listen(timeout))
            if not ok then
                return nil, err, errno
            end
        end
        return true
    end

    function server_methods:localname()
        if self.socket == nil then
            return
        end
        return ca.fileresult(self.socket:localname())
    end

    function server_methods:pause()
        self.paused = true
        self.pause_cond:signal()
        return true
    end

    function server_methods:resume()
        self.paused = false
        self.pause_cond:signal()
        return true
    end

    function server_methods:close()
        if self.cq then
            cqueues.cancel(self.cq:pollfd())
            cqueues.poll()
            cqueues.poll()
            self.cq = nil
        end
        if self.socket then
            self.socket:close()
            self.socket = nil
        end
        self.pause_cond:signal()
        self.connection_done:signal()
        return true
    end

    function server_methods:pollfd()
        return self.cq:pollfd()
    end

    function server_methods:events()
        return self.cq:events()
    end

    function server_methods:timeout()
        return self.cq:timeout()
    end

    function server_methods:empty()
        return self.cq:empty()
    end

    function server_methods:step(...)
        return self.cq:step(...)
    end

    function server_methods:loop(...)
        return self.cq:loop(...)
    end

    function server_methods:add_socket(socket)
        self.n_connections = self.n_connections + 1
        self.cq:wrap(handle_socket, self, socket)
        return true
    end

    function server_methods:add_stream(stream)
        self.cq:wrap(handle_stream, self, stream)
        return true
    end
end

-- 
return {request=request.new_from_uri, listen=server.listen, headers=headers_new, util=util, }
