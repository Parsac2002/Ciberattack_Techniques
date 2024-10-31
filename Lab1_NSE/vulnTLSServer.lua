local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"
local tls = require "tls"
local sslcert = require "sslcert"
local datetime = require "datetime"
local string = require "string"
local unicode = require "unicode"

description = [[
Show alerts about the severity levels of the identified vulnerabilities, inspect the web server’s certificate, and analyze TLS connection.
The vulnerabilities should align with industry best practices, such as:
• OWASP Cheat Sheet,
• Mozilla Server Side TLS Intermediate Configuration
]]

---
-- @usage
-- nmap -p 80 --script vulnTLSServer <ip>
--
-- @output
-- *********************
-- <SEVERITY> ALERTS: <number of these severity alerts>
-- **********************
-- - <Title of alert1>. <Description of alert>
-- - <Title of alert2>. <Description of alert>
-- - ...
-- **********************
authors = "Adriana Companioni Rodriguez & Matias Scarpa Gonzalez"
Alert_types = {
    "Critical",
    "High",
    "Medium",
    "Low"
}
portrule = function (host, port)
    return shortport.ssl(host,port)
end

Cert = nil
Cipher_suite = nil
Critical_table = {}
High_table = {}
Medium_table = {}
Low_table = {}

CRITICAL_count = 0
HIGH_count = 0
MEDIUM_count = 0
LOW_count = 0
SUPPORTED_SUITES = {
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-CHACHA20-POLY1305"
}


-- local function addAlert(alert_tables, alert_title, alert_message)
--     table.insert(alert_tables, {title = alert_title, message = alert_message})    
-- end

-- Critical alerts
-- Self-signed certificates
-- Verifies wether the certificate is self-signed, and if it is, adds a Critical alert to the alerts table.
local isSelfSigned = function(cert)
    if (cert.issuer == cert.subject) then
        CRITICAL_count = CRITICAL_count + 1
        table.insert(Critical_table, {title = "Self-Signed Certificate detected" , message = "."}) 
    end
end
local verify_cipher_suite = function(record)
    
    
    -- Retrieve the cipher suite
    local c = record.body[1].cipher_suite
    Cipher_suite = tls.cipher_info(c)
    local cbc_index = nil
    for _,suite in ipairs(Cipher_suite) do
        _,cbc_index = string.find(suite,"CBC")
        if cbc_index ~= nil then
            if string.find(suite,"SHA",cbc_index) then
                -- Add Critical alert to the table and increment counter
                -- If a cipher suite has CBC & SHA, we count it as 1 problem
                CRITICAL_count = CRITICAL_count + 1
                table.insert(Critical_table, {title = " Cipher includes CBC mode and SHA hash algorithm" , message = "."})
                cbc_index = nil
            end
        
        else
            if string.find(suite,"SHA") then
                CRITICAL_count = CRITICAL_count + 1
                table.insert(Critical_table, {title = "Cipher includes just SHA hash type algorithm" , message = "."})
            end
        end

    end

end

local verify_compression = function(response) 
    if record.body[1].compression_method ~= 0 then
        CRITICAL_count = CRITICAL_count + 1
        table.insert(Critical_table, {title = "Compression STATE:" , message = "ACTIVATED."})
    end


end

-- local verify_cert_type = function()

--     local sign_algorithm = Cert.sig_algorithm
    
-- end
local verify_cert_type = function ()
    
    local cert = ssl.get_cert(host, port) -- Retrieve the certificate

    if cert then
        local algorithm = cert.public_key_algorithm or ""
        local key_size = cert.key_size or 0
        local curve = cert.key_curve or ""

        if algorithm == "RSA" and key_size >= 2048 then
            return "RSA (2048 bits)"
        elseif algorithm == "ECDSA" and key_size == 256 and curve == "P-256" then
            return "ECDSA (P-256)"
        else
            return "Unsupported certificate type or insufficient key size"
        end
    else
        return "No certificate found"
    end
end

action = function(host, port)
    -- Connect to the target server
    local custom_hello
    local status, err
    local sock
    local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
    local response
    custom_hello = tls.client_hello({
        -- TLSv1.3 does not send this extension plaintext.
        -- TODO: implement key exchange crypto to retrieve encrypted extensions
        protocol = "TLSv1.2",
        
    })
    if specialized then
        status, sock = specialized(host, port)
        if not status then
        stdnse.debug1("Connection to server failed: %s", sock)
        return false
        end
    else
        sock = nmap.new_socket()
        status, err = sock:connect(host, port)
        if not status then
        stdnse.debug1("Connection to server failed: %s", err)
        return false
        end
    end

    sock:set_timeout(5000)

    -- Send Client Hello to the target server
    status, err = sock:send(custom_hello)
    if not status then
        stdnse.debug1("Couldn't send: %s", err)
        sock:close()
        return false
    end

    -- Read Response
    status, response, err = tls.record_buffer(sock)
    if not status then
        stdnse.debug1("Couldn't receive: %s", err)
        sock:close()
        return false
    end


    -- Get certificate
    host.targetname = tls.servername(host)
    status, Cert = sslcert.getCertificate(host, port)
    if ( not(status) ) then
        stdnse.debug1("getCertificate error: %s", Cert or "unknown")
        return
    end

    -- Verify message type to be server_hello
    local i, record = tls.record_read(response, 1)
    if record == nil then
        stdnse.debug1("Unknown response from server")
        return nil
    end

    if record.type == "handshake" and record.body[1].type == "server_hello" then
    --? Critical Alerts:
    
    -- Verify Self-Signed
    
    -- Verify Cipher suite

    -- Verify Compression

    --? High Alerts
    -- Verify Cert_type
    end




end



