-- OpenResty / Nginx Lua WAF — php2shell (CVE-2026-109618/109619)
-- access_by_lua_block { require("php2shell").check() }

local _M = {}

local function is_multipart_post()
    if ngx.req.get_method() ~= "POST" then return false end
    local ct = ngx.req.get_headers()["content-type"]
    if not ct then return false end
    return ct:find("multipart/form%-data", 1, false) ~= nil
end

local function get_body(max_size)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        local file = ngx.req.get_body_file()
        if file then
            local fh = io.open(file, "r")
            if fh then
                body = fh:read(max_size or 65536)
                fh:close()
            end
        end
    end
    return body
end

function _M.check(opts)
    opts = opts or {}
    local max_body_read = opts.max_body_read or 65536
    local log_only = opts.log_only or false

    if not is_multipart_post() then return end

    local body = get_body(max_body_read)
    if not body then return end

    -- Block PHP_SESSION_UPLOAD_PROGRESS (primary trigger)
    if body:find("PHP_SESSION_UPLOAD_PROGRESS", 1, true) then
        ngx.log(ngx.WARN,
            "php2shell: blocked upload_progress from ",
            ngx.var.remote_addr, " uri=", ngx.var.request_uri)
        if not log_only then
            ngx.status = 403
            ngx.say("Forbidden")
            return ngx.exit(403)
        end
    end

    -- Detect PHPSESSID in POST body (session fixation)
    if body:find('name="PHPSESSID"', 1, true) then
        ngx.log(ngx.WARN,
            "php2shell: PHPSESSID in POST body from ",
            ngx.var.remote_addr)
    end

    -- Detect PHP code in upload filename (session injection)
    if body:find("<?php", 1, true) or body:find("<?=", 1, true) then
        if body:find('filename="', 1, true) then
            ngx.log(ngx.WARN,
                "php2shell: PHP code in filename from ",
                ngx.var.remote_addr)
            if not log_only then
                ngx.status = 403
                ngx.say("Forbidden")
                return ngx.exit(403)
            end
        end
    end
end

return _M

-- Usage:
--   access_by_lua_block { require("php2shell").check() }
--   access_by_lua_block { require("php2shell").check({ log_only = true }) }
