#!/usr/bin/env bash
# ReconForge — installs missing recon tools via `go install` (preferred) or apt.
set -euo pipefail

GREEN='\033[92m'; YELLOW='\033[93m'; RED='\033[91m'; NC='\033[0m'

have() { command -v "$1" &>/dev/null; }

go_install() {
  local pkg="$1" bin="$2"
  if ! have go; then echo -e "${YELLOW}go not found — installing golang via apt${NC}"; sudo apt-get install -y golang-go >/dev/null 2>&1 || true; fi
  if have go; then
    echo -e "${GREEN}go install ${bin}${NC}"
    GOBIN="${HOME}/go/bin" go install "${pkg}@latest"
  fi
}

echo -e "${GREEN}=== ReconForge tool installer ===${NC}"

# projectdiscovery essentials
for entry in \
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder subfinder" \
  "github.com/projectdiscovery/httpx/cmd/httpx httpx" \
  "github.com/projectdiscovery/dnsx/cmd/dnsx dnsx" \
  "github.com/projectdiscovery/naabu/v2/cmd/naabu naabu" \
  "github.com/projectdiscovery/katana/cmd/katana katana" \
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei nuclei"; do
  pkg="${entry% *}"; bin="${entry##* }"
  if ! have "$bin" && [ ! -x "${HOME}/go/bin/$bin" ]; then go_install "$pkg" "$bin"; else echo -e "  ${GREEN}✓${NC} $bin already installed"; fi
done

# gau / waybackurls
for entry in \
  "github.com/tomnomnom/waybackurls waybackurls" \
  "github.com/lc/gau/v2/cmd/gau gau"; do
  pkg="${entry% *}"; bin="${entry##* }"
  if ! have "$bin" && [ ! -x "${HOME}/go/bin/$bin" ]; then go_install "$pkg" "$bin"; fi
done

# ffuf, dalfox, subzy, gowitness
for entry in \
  "github.com/ffuf/ffuf/v2 ffuf" \
  "github.com/hahwul/dalfox/v2 dalfox" \
  "github.com/PentestPad/subzy subzy" \
  "github.com/sensepost/gowitness gowitness"; do
  pkg="${entry% *}"; bin="${entry##* }"
  if ! have "$bin" && [ ! -x "${HOME}/go/bin/$bin" ]; then go_install "$pkg" "$bin"; fi
done

# amass via apt is fine (slower versions ok)
if ! have amass; then sudo apt-get install -y amass >/dev/null 2>&1 || true; fi

echo -e "${GREEN}=== Done. Verify with: reconforge tools ===${NC}"
