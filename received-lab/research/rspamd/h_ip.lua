-- Register explicitly. The return-table form loaded but did not emit a symbol.
local symbol = 'H_SOURCE_IP'

local function h_ip_cb(task)
    local ip = task:get_from_ip()
    local host = task:get_hostname()
    local value
    if ip and ip:is_valid() then
        value = tostring(ip) .. '|' .. tostring(host)
    else
        value = 'NO_IP|' .. tostring(host)
    end
    task:insert_result(symbol, 0.0, value)
end

rspamd_config:register_symbol({
    name = symbol,
    type = 'normal',
    callback = h_ip_cb,
    score = 0.0,
})
