local dns = require "dns"
local shortport = require "shortport"

description = [[ Formats DNS query output into structured tab-delimited records. ]]
author = "Shubhra Negi"
license = "Same as Nmap"
categories = {"discovery", "safe"}

portrule = shortport.portnumber(53, "udp")

action = function(host, port)
  local output = {}
  local domain = "google.com"

  local status, result = dns.query(domain, {host = host.ip, port = port.number, dtype = "A"})
  if status and result then
    table.insert(output, string.format("DNS_RECORD\tA\t%s\t%s", domain, tostring(result[1] or "SUCCESS")))
  end

  if #output > 0 then
    return table.concat(output, "\n")
  end
  return nil
end
