---
name: App Icon Management
description: Standard procedure for generating and managing GTrace application icons for Windows and macOS.
---

# App Icon Management

This skill documents the process of generating high-quality consistency application icons for GTrace on both Windows and macOS. It addresses specific issues encountered during development, such as "black border artifacts" and platform inconsistencies.

## 1. Source Material

*   **Source File**: `build/appicon_source_highres.png`
*   **Requirements**: A high-resolution (at least 1024x1024) PNG image.
*   **Location**: This file is checked into the repository to ensure reproducibility.

## 2. Generation Tool

We use a custom Go script to automate the processing pipeline.

*   **Script Path**: `tools/finalize_icon.go`
*   **Capabilities**:
    *   **Standardization**: Resizes and formats the source image.
    *   **Artifact Removal**: Applies a **1.25x zoom (crop)** to remove persistent black borders found in the source material.
    *   **Squircle Masking**: Applies a high-quality "Squircle" (Apple super-ellipse) mask with tight edge softening (< 3px) to ensure crisp edges without blurring or dark halos.
    *   **Format Conversion**:
        *   `build/appicon.png`: Standard Wails app icon.
        *   `build/windows/icon.ico`: Native Windows icon (multi-size not strictly required by Wails but generated as valid ICO).
        *   `build/darwin/icon.icns`: Native macOS icon bundle, generated using system tools (`sips`, `iconutil`).

## 3. How to Update Icons

If you change the source image `build/appicon_source_highres.png`, run the following command to regeneration all platform icons:

```bash
go run tools/finalize_icon.go
```

**Note**: macOS `.icns` generation requires running on a macOS host with `sips` and `iconutil` available (standard on macOS).

## 4. Build Integration

Wails uses the generated assets during the build process.

*   **Windows**: Uses `build/windows/icon.ico`.
*   **macOS**: Uses `build/darwin/icon.icns`.

To apply the new icons, rebuild the application:

```bash
# Clean previous build artifacts usually helps
rm -rf build/bin/*

# Build
wails build
```

## 5. Troubleshooting History

### Issue: "Black Circle" / Dark Border Artifacts
*   **Symptom**: The icon appeared to have a rough black outline or "container" on both Windows and macOS.
*   **Cause**: The source image had a built-in dark frame/border, and the previous scaling didn't crop it out completely. Also, the alpha mask feathering was too wide (15px), causing the dark border to bleed into the visible area.
*   **Fix**:
    1.  **Zoom Factor**: Increased cropping zoom to **1.25x** in `finalize_icon.go`.
    2.  **Edge Sharpening**: Reduced alpha mask soft threshold to `0.997 - 1.003` (approx 2-3px) for a sharper cut.

### Issue: Windows/Mac Inconsistency
*   **Symptom**: Windows icon looked different (e.g., missing background or transparent) compared to Mac.
*   **Cause**: The build process was missing a dedicated `icon.ico` derived from the same logic as the Mac icon, defaulting to a stale or generic file.
*   **Fix**: The `finalize_icon.go` script now explicitly generates `build/windows/icon.ico` using the same source and processing logic as the Mac version.
