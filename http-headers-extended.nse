local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[ Filters and extracts target HTTP protocol and security response headers. ]]
author = "Shubhra Negi"
license = "Same as Nmap"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local response = http.get(host, port, "/")
  if not response or not response.header then return nil end

  local target_keys = {
    "server", 
    "strict-transport-security", 
    "content-security-policy", 
    "x-frame-options", 
    "x-content-type-options",
    "x-xss-protection"
  }

  local output = {}
  for _, key in ipairs(target_keys) do
    if response.header[key] then
      table.insert(output, string.format("%s: %s", key, response.header[key]))
    end
  end

  return stdnse.format_output(true, output)
end
