# Quorix Safe-Zone SOC Dashboard Guidelines

## 1. UI Framework & Styling
- **Modern UI Frameworks Allowed**: You are ENCOURAGED to use modern UI libraries (e.g., Tailwind CSS, Shadcn UI, Headless UI, Radix, Material UI) to speed up development and ensure high-quality, robust components.
- **Tailwind CSS**: Tailwind CSS is fully permitted and recommended for rapid styling and layout management.
- **Charts**: Use modern, robust charting libraries (like Recharts, ApexCharts, etc.) that support SVG/DOM animations easily, instead of being constrained by Canvas-only libraries if advanced animations are required.

## 2. Aesthetics & Design System (Premium SOC Vibe)
- **Theme**: Light, Modern Artistic SOC (Security Operations Center) - inspired by Windows 11 / Zorin OS.
- **Color Palette**: Bright and clean backgrounds (White, Light Gray, Very Light Pink). Use clear accent colors for states (Red for Threats, Yellow for Suspicious, Green for Safe, Blue for Info).
- **Modern Polish**: Use modern web design trends like glassmorphism (backdrop-blur with light frosted glass), clean typography. The UI should look artistic, high-tech, clean and professional.

## 3. Animations & Interactions
- **Micro-interactions**: Ensure interactive elements (buttons, rows, dropdowns) have snappy hover states and transitions.
- **Data Rendering**: Use layout animations (like Framer Motion or Tailwind transitions) to ensure data appears smoothly (fade-in, slide-in) without jarring layout shifts (CLS).

## 4. Scripts Organization & Naming Conventions
- **Directory Structure**: The `scripts` directory must be categorized logically. Subdirectories should be named in lowercase, using plural nouns (e.g., `scrapers`, `verifiers`, `ops`, `generators`, `data_processing`). 
- **File Naming**:
  - Python Scripts: Use `snake_case` (e.g., `scrape_vietnam_blacklist.py`).
  - Shell/PowerShell Scripts: Use `kebab-case` (e.g., `safe-zone.sh`, `ui.ps1`).
- **Location**: Scripts must be placed in their respective subdirectories based on their function. Do not place new scripts directly in the root of the `scripts/` folder.

## 5. AI Engine Development Documentation
- **Mandatory Logging**: Bất kể khi thực hiện bất kỳ thao tác nào để phát triển AI engine, đều phải cập nhật tiến trình, phương pháp và thay đổi vào `D:\Quorix\services\safe-zone\docs\research\ml\method.md`.
- **Quality of Information**: Thông tin phải rõ ràng, minh bạch, không dài dòng. Mọi thông tin thêm vào đều phải có giá trị.
