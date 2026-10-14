-- ratelimit.lua
-- Sliding-window LOG rate limiter (OpenResty + Redis) - production version.
--
-- Deployment topology this assumes:
--   client -> Apache (443, mod_security2 WAF) -> OpenResty (127.0.0.1:8082)
--          -> backend webapp (x.x.x.x:9003)
--
-- Changes from the previous version, and why:
--
--   1. CLIENT IP: taken from ngx.var.remote_addr, which nginx's real_ip
--      module has already resolved from X-Forwarded-For while trusting ONLY
--      the local Apache hop (see set_real_ip_from in nginx.conf). The old
--      code read the FIRST value of the raw X-Forwarded-For header, which
--      any client can set themselves - so a client sending a random
--      X-Forwarded-For on every request got a brand new bucket every time
--      and was never limited. That is a bypass, not a cosmetic issue.
--
--   2. UNIQUE MEMBER ID: the sorted-set member now uses ngx.var.request_id
--      (unique per request) instead of math.random inside the Redis script.
--      Redis seeds math.random deterministically for scripts, so the same
--      value can repeat; if two requests for the same key land in the same
--      millisecond AND draw the same number, ZADD updates the existing
--      member instead of adding a new one, silently undercounting. That is
--      exactly the failure mode a 20-thread JMeter run provokes.
--
--   3. LOGGING: the per-request debug line is at INFO, not ERR, so it does
--      not flood error.log in production. Raise error_log to info in
--      nginx.conf when you want to see it.

local redis = require "resty.redis"

-- ============================================================
-- Configuration
-- ============================================================
local REDIS_HOST        = "127.0.0.1"      -- docker-compose service name
local REDIS_PORT        = 6379
local REDIS_TIMEOUT_MS  = 100
local WINDOW_SECONDS    = 60
local MAX_REQUESTS      = 400
local KEY_PREFIX        = "rl:usage:"

-- ============================================================
-- Client identity
-- remote_addr is the real client IP AFTER real_ip processing in nginx.conf.
-- ============================================================
local client_ip = ngx.var.remote_addr
if not client_ip or client_ip == "" then
    ngx.log(ngx.ERR, "rate_limit: could not determine client IP")
    return -- fail open
end

local key = KEY_PREFIX .. client_ip

-- ============================================================
-- Redis connection (returned to the pool via set_keepalive below)
-- ============================================================
local red = redis:new()
red:set_timeouts(REDIS_TIMEOUT_MS, REDIS_TIMEOUT_MS, REDIS_TIMEOUT_MS)

local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
if not ok then
    ngx.log(ngx.ERR, "rate_limit: failed to connect to Redis: ", err)
    return -- fail open; use ngx.exit(503) here to fail closed instead
end

-- ============================================================
-- Atomic sliding-window check-and-record, executed inside Redis.
--
--   KEYS[1] = sorted-set key for this client
--   ARGV[1] = now, in milliseconds
--   ARGV[2] = window size, in milliseconds
--   ARGV[3] = max requests allowed in the window
--   ARGV[4] = unique member id for this request
--
-- Returns { allowed (1|0), count_in_window }
--
-- All four Redis commands run as one indivisible unit, so no two
-- concurrent requests can both read the same count before either writes.
-- ============================================================
local SCRIPT = [[
local key          = KEYS[1]
local now_ms       = tonumber(ARGV[1])
local window_ms    = tonumber(ARGV[2])
local max_requests = tonumber(ARGV[3])
local member       = ARGV[4]

redis.call("ZREMRANGEBYSCORE", key, "-inf", now_ms - window_ms)

local current_count = redis.call("ZCARD", key)
if current_count >= max_requests then
    return { 0, current_count }
end

redis.call("ZADD", key, now_ms, member)
redis.call("PEXPIRE", key, window_ms * 2)

return { 1, current_count + 1 }
]]

local now_ms = math.floor(ngx.now() * 1000)
local member = now_ms .. "-" .. ngx.var.request_id

local res, eval_err = red:eval(SCRIPT, 1, key, now_ms,
                               WINDOW_SECONDS * 1000, MAX_REQUESTS, member)

local ok2, pool_err = red:set_keepalive(10000, 100)
if not ok2 then
    ngx.log(ngx.WARN, "rate_limit: failed to set Redis keepalive: ", pool_err)
end

if not res then
    ngx.log(ngx.ERR, "rate_limit: EVAL failed: ", eval_err)
    return -- fail open
end

local allowed       = res[1]
local current_count = res[2]

ngx.var.rl_count = tostring(current_count)
ngx.var.rl_key   = client_ip

ngx.log(ngx.INFO, "rate_limit: IP=", client_ip,
        " COUNT=", current_count, " ALLOWED=", allowed)

if allowed == 0 then
    ngx.status = 429
    ngx.header["Retry-After"]  = tostring(WINDOW_SECONDS)
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error":"rate limit exceeded","limit":' .. MAX_REQUESTS ..
            ',"window_seconds":' .. WINDOW_SECONDS .. '}')
    return ngx.exit(429)
end