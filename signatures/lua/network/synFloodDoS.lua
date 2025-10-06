-- Load NSE libraries required for network I/O and packet crafting
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local shortport = require "shortport"

-- NSE Documentation and Metadata
description = [[
Sends a single, raw TCP SYN packet to a port to verify its state by analyzing
the raw TCP response. This script demonstrates low-level TCP handshake manipulation.
]]

---
-- @usage
-- nmap -p 80,443,8080 --script custom-syn-check.nse <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | custom-syn-check:
-- |   VULNERABLE:
-- |   Evidence: Received a SYN-ACK response, confirming the port is open.
-- |   Severity: INFO
--
-- @args custom-syn-check.timeout The timeout to wait for a reply in ms. Default: 1000
---

author = "Vulcan"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

-- Only run this script against TCP ports.
portrule = shortport.port_or_service_with_version(nil, "tcp", "open")

action = function(host, port)
  -- =========================================================================
  -- METADATA BLOCK (Defined in NSE header and here for clarity)
  -- =========================================================================
  local signature_metadata = {
    unique_identifier = 'TCP-RAW-SYN-CHECK-1.0',
    targeting_criteria = 'Any listening TCP port',
    severity = 'INFO' -- This is a recon script, not an exploit.
  }

  local result = {
    vulnerable = false, -- In this context, "vulnerable" means the check succeeded.
    evidence = '',
    metadata = signature_metadata
  }

  -- =========================================================================
  -- PHASE 1: PROBE (Pre-condition Check)
  -- =========================================================================
  -- The Nmap engine itself acts as the probe. By the time this script's
  -- 'action' function is called, Nmap has already confirmed the host is up
  -- and the port is in a state worth checking ('open' per our portrule).
  -- This prevents the script from running against dead hosts or irrelevant ports.

  -- =========================================================================
  -- PHASE 2: TRIGGER (The Active Check)
  -- =========================================================================
  -- Craft a raw TCP SYN packet from scratch.

  local dport = port.number
  local sport = math.random(1025, 65535) -- Use a random high source port
  local timeout = stdnse.get_script_args("custom-syn-check.timeout") or 1000

  -- 1. Create a new raw socket
  local sock = nmap.new_socket()
  if not sock then
    result.evidence = "Failed to create new socket."
    return stdnse.format_output(false, result)
  end
  sock:set_timeout(timeout)

  -- 2. Craft the TCP Packet
  -- Create an IP header with our host and the target host
  local ip_header = packet.ip_new()
  ip_header.src = nmap.get_interface_ip(host.interface)
  ip_header.dst = host.ip
  ip_header.p = 6 -- Protocol 6 is TCP

  -- Create a TCP header with flags set to SYN
  local tcp_header = packet.tcp_new()
  tcp_header.src = sport
  tcp_header.dst = dport
  tcp_header.seq = math.random(0, 0xFFFFFFFF) -- Random initial sequence number
  tcp_header.flags = { SYN = 1 } -- This is the key part of the trigger
  tcp_header.win = 1024

  -- 3. Link headers, calculate checksums, and send
  ip_header.data = tcp_header
  local status, err = packet.build_ip(ip_header)
  if not status then
    result.evidence = "Failed to build IP packet: " .. err
    return stdnse.format_output(false, result)
  end
  
  -- Send the packet
  sock:send(ip_header)

  -- =========================================================================
  -- PHASE 3: VERIFY (Post-condition Analysis)
  -- =========================================================================
  -- Listen for the raw IP packet reply from the target.

  local response_status, response_packet = sock:receive_ip_packet()
  sock:close()

  if not response_status then
    -- No response means the packet was likely dropped (filtered)
    result.evidence = "Verification failed. No response received (port is likely filtered)."
    return stdnse.format_output(false, result)
  end

  -- Parse the response to check its TCP flags
  local _, _, _, _, _, response_tcp_header = packet.parse_ip_packet(response_packet)
  if response_tcp_header then
    -- High-confidence check: A SYN-ACK response means the port is open and listening.
    if response_tcp_header.flags.SYN and response_tcp_header.flags.ACK then
      result.vulnerable = true -- 'Success' in this context
      result.evidence = "Received a SYN-ACK response, confirming the port is open."
    -- High-confidence check: A RST-ACK response means the port is actively closed.
    elseif response_tcp_header.flags.RST then
      result.evidence = "Received a RST-ACK response, confirming the port is closed."
    else
      result.evidence = "Received an unexpected TCP response."
    end
  else
    result.evidence = "Received a non-TCP response."
  end

  return stdnse.format_output(result.vulnerable, result)
end
