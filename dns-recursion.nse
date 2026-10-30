local dns = require "dns"
local shortport = require "shortport"

description = [[ Checks if a DNS server responds to recursive queries. ]]
author = "Nmap Community"
license = "Same as Nmap"
categories = {"discovery", "safe"}

portrule = shortport.portnumber(53, "udp")

action = function(host, port)
  local status, result = dns.query("www.google.com", {host = host.ip, port = port.number, rd = true})
  if status then
    return "Recursion appears to be enabled"
  end
  return nil
end
