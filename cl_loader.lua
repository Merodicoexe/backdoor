-- Tento kód bude skutečně printovat
CreateThread(function()
    while true do
        Wait(0)
        print("[REMOTE CLIENT] Tento print běží každých 5 sekund")
    end
end)
