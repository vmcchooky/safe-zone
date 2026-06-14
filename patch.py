import os
import re

for filename in ["internal/api/handlers/block.go", "internal/api/handlers/dashboard.go"]:
    with open(filename, "r", encoding="utf-8") as f:
        content = f.read()
    
    content = content.replace("package main", "package handlers")
    content = content.replace("(a *app)", "(h *Handler)")
    content = content.replace("writeError(", "httputil.WriteError(")
    content = content.replace("a.risk", "h.Risk")
    
    # Capitalize the method names since they must be exported
    content = content.replace("func (h *Handler) blockPageHandler", "func (h *Handler) BlockPageHandler")
    content = content.replace("func (h *Handler) blockReportHandler", "func (h *Handler) BlockReportHandler")
    content = content.replace("func (h *Handler) dashboardHandler", "func (h *Handler) DashboardHandler")
    
    # Add "safe-zone/internal/api/httputil" to imports if writeError was replaced
    if "httputil.WriteError" in content and '"safe-zone/internal/api/httputil"' not in content:
        content = content.replace('"time"', '"time"\n\t"safe-zone/internal/api/httputil"')
        
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)
