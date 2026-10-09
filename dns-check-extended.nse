local dns = require "dns"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[ Queries raw A, MX, and NS DNS resource records. ]]
author = "Shubhra Negi"
license = "Same as Nmap"
categories = {"discovery", "safe"}

portrule = shortport.portnumber(53, "udp")

action = function(host, port)
  local output = {}
  local domain = "google.com"

  local status, result = dns.query(domain, {host = host.ip, port = port.number, dtype = "A"})
  if status and result then
    table.insert(output, string.format("Query: %s (Type A)", domain))
    table.insert(output, string.format("Response Address: %s", tostring(result[1] or "Received")))
  end

  if #output > 0 then
    return stdnse.format_output(true, output)
  end
  return nil
end
