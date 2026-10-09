local http = require "http"
local shortport = require "shortport"

description = [[ Outputs all HTTP response headers in pipe-delimited key-value format. ]]
author = "Shubhra Negi"
license = "Same as Nmap"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local response = http.get(host, port, "/")
  if not response or not response.header then return nil end

  local output = {}
  for key, value in pairs(response.header) do
    local clean_val = tostring(value):gsub("\n", " "):gsub("\r", "")
    table.insert(output, string.format("HEADER|%s|%s", tostring(key), clean_val))
  end

  return table.concat(output, "\n")
end

