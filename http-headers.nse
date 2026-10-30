local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[ Fetches raw HTTP headers from the target server. ]]
author = "Nmap Community"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

action = function(host, port)
  local response = http.get(host, port, "/")
  if not response or not response.rawheader then
    return nil
  end
  return stdnse.format_output(true, response.rawheader)
end
