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
-- nmap -p 80 --script vulnTLSServer <host>
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
    "TLS_ECDHE_ECDSA_AES128_GCM_SHA256",
    "TLS_ECDHE_RSA_AES128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_AES256_GCM_SHA384",
    "TLS_ECDHE_RSA_AES256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_CHACHA20_POLY1305",
    "TLS_ECDHE_RSA_CHACHA20_POLY1305",
    "TLS_DHE_RSA_AES128_GCM_SHA256",
    "TLS_DHE_RSA_AES256_GCM_SHA384",
    "TLS_DHE_RSA_CHACHA20_POLY1305"
}

SHA1_ciphers_without_cbc = {
    -- RC4 Stream Cipher (SHA-1) - Deprecated due to known weaknesses
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",

}

CBC_ciphers_without_sha1 = {
    -- RSA Key Exchange (CBC, SHA-256 or SHA-384)
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",

    -- ECDHE Key Exchange (CBC, SHA-256 or SHA-384)
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",

    -- DHE Key Exchange (CBC, SHA-256 or SHA-384)
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",

    -- DH Key Exchange (CBC, SHA-256 or SHA-384)
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA256"
}

SHA1_CBC_ciphers = {
    -- RSA Key Exchange (CBC, SHA-1)
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",

    -- ECDHE Key Exchange (CBC, SHA-1)
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",

    -- DHE Key Exchange (CBC, SHA-1)
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",

    -- DH Key Exchange (CBC, SHA-1)
    "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
    "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
    "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
    "TLS_DH_DSS_WITH_AES_256_CBC_SHA",

    -- 3DES (CBC, SHA-1)
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
    "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"
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
    	stdnse.debug1("Self-Signed Certificate detected !!!")
    else
        stdnse.debug1("Certificate is not self-signed")
    end
end
local verify_cipher_suite = function(record)
    
    
    -- Retrieve the cipher suite
    local c = record.body[1].cipher
    stdnse.debug("Cipher %s.", record.body[1].cipher)
    Cipher_suite = tls.cipher_info(c)
    stdnse.debug("Mode: %s && Hash Algo: %s", Cipher_suite.mode, Cipher_suite.hash)
    if Cipher_suite.mode == "CBC" and Cipher_suite.hash == "SHA" then
        CRITICAL_count = CRITICAL_count + 1
        table.insert(Critical_table, {title = " Cipher includes CBC mode and SHA hash algorithm" , message = "."})
    elseif Cipher_suite.mode == "CBC" then
        CRITICAL_count = CRITICAL_count + 1
        table.insert(Critical_table, {title = "Cipher includes just CBC mode" , message = "."})
    elseif Cipher_suite.hash == "SHA" then
        CRITICAL_count = CRITICAL_count + 1
        table.insert(Critical_table, {title = "Cipher includes just SHA hash type algorithm" , message = "."})
    end
    
    
    

end

local verify_compression = function(record) 
    stdnse.debug("Negociated compressor: %s", record.body[1].compressor)
    if record.body[1].compressor ~= 0 then
        CRITICAL_count = CRITICAL_count + 1
        table.insert(Critical_table, {title = "Compression STATE:" , message = "ACTIVATED."})
    end


end

-- local verify_cert_type = function()

--     local sign_algorithm = Cert.sig_algorithm
    
-- end
local verify_cert_type = function (cert)
    
    -- local cert = ssl.get_cert(host, port) -- Retrieve the certificate

    if cert then
        local algorithm = cert.pubkey.type
        local key_size = cert.pubkey.bits
        if algorithm == "rsa" and key_size >= 2048 then
            stdnse.debug("RSA (%d bits)", key_size)
        elseif algorithm == "ecdsa" and key_size == 256 then
            stdnse.debug("ECDSA (P-256)")
        else
            HIGH_count = HIGH_count + 1
            table.insert(High_table, {title = "Unsupported certificate type or insufficient key size" , message = string.format("Algorithm: %s, Key size: %d bits", algorithm, key_size)})
        end
    else
        stdnse.debug("No certificate found")
    end
end

local function send_hello(hello_msg, host, port)
    local status, err
    local sock
    local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
    local response

    stdnse.debug1("Initiating socket connection...")
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
    stdnse.debug1("Socket connection success && Setting timeout...")

    sock:set_timeout(5000)

    stdnse.debug1("Send Client Hello to the target server...")
    -- Send Client Hello to the target server
    status, err = sock:send(hello_msg)
    if not status then
        stdnse.debug1("Couldn't send: %s", err)
        sock:close()
        return false
    end

    stdnse.debug1("Reading response...")
    
    -- Read Response
    status, response, err = tls.record_buffer(sock)
    stdnse.debug1("status: %s", status)
    if not status then
        stdnse.debug1("Couldn't receive: %s", err)
        sock:close()
        return false
    end
    
    local i, record = tls.record_read(response, 1)
    if record == nil then
        stdnse.debug1("Unknown response from server")
        return nil
    end
    return record
end

local function check_supported_ciphers(host, port)
    local custom_hello = tls.client_hello({
        protocol = "TLSv1.2",
        -- ciphers = SUPPORTED_SUITES
        ciphers = CBC_ciphers_without_sha1
    })
    local record = send_hello(custom_hello, host, port)
 
end

-- True: handshake has failed
-- False: handshake has succeeded
local function check_handshake_failure(record)
    if record.type == "alert" and record.body[1].description == "handshake_failure" then
        stdnse.debug1("Handshake failed")
        return true
    else
        stdnse.debug1("Handshake succeeded")
        return false
    end
end

local function check_validity(cert)
    local notBefore = cert.validity.notBefore --ambos tablas
    local notAfter = cert.validity.notAfter
    --print(string.format("Not Before: %s", notBefore))
    --print(string.format("Not After: %s", notAfter))

    -- Convertir las fechas a formato de tabla de tiempo
    -- local notBefore_time = datetime.parse_timestamp(notBefore)
    -- local notAfter_time = datetime.parse_timestamp(notAfter)
    local notBefore_seconds = datetime.date_to_timestamp(notBefore)
    local notAfter_seconds = datetime.date_to_timestamp(notAfter)
    local time_diff_days = (notAfter_seconds - notBefore_seconds)/(24*3600)

    if time_diff_days < 90 or time_diff_days > 366 then
        MEDIUM_count = MEDIUM_count + 1
        table.insert(Medium_table, {title = "Invalid certificate validity period" , message = string.format("Validity period: %d days", time_diff_days)})
        stdnse.debug(string.format("Validity period: %d days", time_diff_days))
    end
    stdnse.debug(string.format("Validity period: %d days", time_diff_days))
end

local function compare_CN_with_domain_name(cert, host)
    -- host.targetname = tls.servername(host)
    local CN = cert.subject.commonName

    if host.targetname ~= CN then
        MEDIUM_count = MEDIUM_count + 1
        table.insert(Medium_table, {title = "Common name (CN) doesn't match Domain Name" , message = string.format("CN: %s & Domain Name: %s ", CN,host.targetname )})
        stdnse.debug(string.format("CN: %s & Domain Name: %s ", CN,host.targetname ))
    else
        stdnse.debug(string.format("EQUAL: CN: %s & Domain Name: %s ", CN,host.targetname ))
    end
end    

action = function(host, port)
    -- Connect to the target server
    local custom_hello
    local status
    local success_supported_cihpers = false
    stdnse.debug1("Preparing custom hello...")
    custom_hello = tls.client_hello({
        -- TLSv1.3 does not send this extension plaintext.
        -- TODO: implement key exchange crypto to retrieve encrypted extensions
        protocol = "TLSv1.2",
        ciphers = SHA1_CBC_ciphers,
        compressors = {"DEFLATE","LZS"}
        -- compressors = {"LZS"}
    })
    
    local record = send_hello(custom_hello, host, port)
    local failure = check_handshake_failure(record)
    if failure then
        custom_hello.ciphers = CBC_ciphers_without_sha1
        record = send_hello(custom_hello, host, port)
        failure = check_handshake_failure(record)
        if failure then
            custom_hello.ciphers = SHA1_ciphers_without_cbc
            record = send_hello(custom_hello, host, port)
            failure = check_handshake_failure(record)
            if failure then
                success_supported_cihpers = true
                stdnse.debug("No CBC and SHA1 ciphers are supported")
                check_supported_ciphers(host, port)
            end
        end
    end
    
    
    -- Get certificate
    host.targetname = tls.servername(host)
    status, Cert = sslcert.getCertificate(host, port)
    
    if ( not(status) ) then
        stdnse.debug1("getCertificate error: %s", Cert or "unknown")
        return
    end
    
    --get_body(record)
    if record and record.body and record.body[1] then
        stdnse.debug1("Record type: %s and body type: %s", record.type, record.body[1].type)
    else
        stdnse.debug1("Record or record body is nil")
    end
    
    if record.type == "handshake" and record.body[1].type == "server_hello" then
        --? Critical Alerts:
        
        -- Verify Self-Signed
        isSelfSigned(Cert)
        -- Verify Compression
            -- Possible values:
            -- "NULL"
            -- "DEFLATE"
            -- "LZS"
        verify_compression(record)
        -- Verify Cipher suite
        verify_cipher_suite(record)

        --? High Alerts
        -- Verify Cert_type
        verify_cert_type(Cert)
        if not success_supported_cihpers then
            check_supported_ciphers(host, port)
        end
        check_validity(Cert)
        compare_CN_with_domain_name(Cert, host)
    end




end


-- Function = client_hello(t)

