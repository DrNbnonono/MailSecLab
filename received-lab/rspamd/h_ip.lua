-- H-series observable: expose rspamd's derived source IP + hostname as a symbol
local symbol = 'H_SOURCE_IP'
local function h_ip_cb(task)
    local ip = task:get_from_ip()
    local host = task:get_hostname()
    if ip and ip:is_valid() then
        task:result(symbol, 0.0, tostring(ip) .. '|' .. tostring(host))
    else
        task:result(symbol, 0.0, 'NO_IP|' .. tostring(host))
    end
end
return {
    symbols = { { symbol = symbol, callback = h_ip_cb } }
}
