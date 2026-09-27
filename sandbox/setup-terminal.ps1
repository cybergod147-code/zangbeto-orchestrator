# setup-terminal.ps1
# Rebuilds zangbeto-kali-terminal with all tools + tmux session

Write-Host "Setting up Zangbeto shared terminal..." -ForegroundColor Cyan

# Check if container exists and is running
$exists = docker ps -a --filter "name=zangbeto-kali-terminal" --format "{{.Names}}"

if ($exists) {
    Write-Host "Removing old container..." -ForegroundColor Yellow
    docker stop zangbeto-kali-terminal 2>$null
    docker rm zangbeto-kali-terminal 2>$null
}

Write-Host "Creating fresh container..." -ForegroundColor Cyan
docker run -d --name zangbeto-kali-terminal --cap-add=NET_RAW --cap-add=NET_ADMIN -p 7681:7681 zangbeto-sandbox sleep infinity

Write-Host "Waiting for container to boot..." -ForegroundColor Cyan
Start-Sleep -Seconds 3

Write-Host "Installing tmux, unzip, ttyd..." -ForegroundColor Cyan
docker exec zangbeto-kali-terminal bash -c "apt-get update -qq && apt-get install -y -qq tmux unzip wget"
docker exec zangbeto-kali-terminal bash -c "wget -q -O /usr/local/bin/ttyd https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 && chmod +x /usr/local/bin/ttyd"

Write-Host "Installing Nuclei, Subfinder, HTTPX..." -ForegroundColor Cyan
docker exec zangbeto-kali-terminal bash -c "cd /tmp && wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_linux_amd64.zip && unzip -o nuclei_3.3.5_linux_amd64.zip > /dev/null && mv nuclei /usr/local/bin/ && chmod +x /usr/local/bin/nuclei"
docker exec zangbeto-kali-terminal bash -c "cd /tmp && wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && unzip -o subfinder_2.6.6_linux_amd64.zip > /dev/null && mv subfinder /usr/local/bin/ && chmod +x /usr/local/bin/subfinder"
docker exec zangbeto-kali-terminal bash -c "cd /tmp && wget -q https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip && unzip -o httpx_1.6.9_linux_amd64.zip > /dev/null && mv httpx /usr/local/bin/ && chmod +x /usr/local/bin/httpx"

Write-Host "Starting tmux shared session..." -ForegroundColor Cyan
docker exec -d zangbeto-kali-terminal tmux new-session -d -s shared
Start-Sleep -Seconds 1
docker exec -d zangbeto-kali-terminal ttyd -p 7681 -W --interface 0.0.0.0 tmux attach -t shared

Write-Host ""
Write-Host "✅ Zangbeto shared terminal ready!" -ForegroundColor Green
Write-Host "   URL: http://localhost:7681" -ForegroundColor Green
Write-Host "   Session: shared (tmux)" -ForegroundColor Green