package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	_ "image/jpeg"
)

func main() {
	// 1. Configuration: Apple Standard 82.5%
	// Canvas: 1024x1024
	// Content Size: 845x845 (The visual weight of the icon)
	const canvasSize = 1024
	const iconSize = 845.0

	// Input File (High Res Source)
	inputPath := "build/appicon_source_highres.png"
	outputPath := "build/appicon.png"

	f, err := os.Open(inputPath)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	src, _, err := image.Decode(f)
	if err != nil {
		panic(err)
	}

	// 2. Setup Canvas
	canvas := image.NewRGBA(image.Rect(0, 0, canvasSize, canvasSize))
	draw.Draw(canvas, canvas.Bounds(), &image.Uniform{color.Transparent}, image.Point{}, draw.Src)

	// 3. Geometry Setup
	halfSize := iconSize / 2.0
	center := float64(canvasSize) / 2.0

	srcBounds := src.Bounds()
	sw, sh := float64(srcBounds.Dx()), float64(srcBounds.Dy())
	// Center of source
	scx, scy := float64(srcBounds.Min.X)+sw/2.0, float64(srcBounds.Min.Y)+sh/2.0

	// Zoom factor to fit content nicely inside the mask
	// Scaling factor mapping target (iconSize) to source (sw)
	// UPDATE: Zoom in by 18% to aggressively crop out the black frame in the source image
	// UPDATE: Zoom in significantly (25%) to ensure no border artifacts remain
	scale := sw / (iconSize * 1.25)

	// 4. Processing Loop
	for y := 0; y < canvasSize; y++ {
		for x := 0; x < canvasSize; x++ {
			// Relative position to icon center
			relX := float64(x) - center + 0.5
			relY := float64(y) - center + 0.5

			// Normalize coordinates (-1 to 1) based on iconSize
			nx := math.Abs(relX) / halfSize
			ny := math.Abs(relY) / halfSize

			// 5. Apple Squircle Formula: d = (x^4 + y^4)^(1/4)
			dist := math.Pow(math.Pow(nx, 4)+math.Pow(ny, 4), 0.25)

			// 6. Antialiased Masking
			// High-quality edge: ~2-3 pixels softnes (Standard for high-res icons)
			// Normalized pixel size is approx 1/512 = ~0.002
			// Let's us a range of +/- 0.003 around 1.0
			var alpha float64
			lower := 0.997
			upper := 1.003

			if dist <= lower {
				alpha = 1.0
			} else if dist >= upper {
				alpha = 0.0
			} else {
				alpha = (upper - dist) / (upper - lower)
			}

			if alpha > 0 {
				// Map canvas pixel back to source pixel
				srcX := int(scx + relX*scale)
				srcY := int(scy + relY*scale)

				// Bounds check
				if srcX >= srcBounds.Min.X && srcX < srcBounds.Max.X &&
					srcY >= srcBounds.Min.Y && srcY < srcBounds.Max.Y {

					c := src.At(srcX, srcY)
					r, g, b, aRaw := c.RGBA()

					// Just apply the mask to the existing alpha
					finalA := uint8((float64(aRaw>>8) * alpha))

					// Remove pure black artifacts if necessary (optional, keeping simple for now)
					// (Re-adding the simple luma check if desired, but user just wants black circle gone)

					if finalA > 0 {
						canvas.Set(x, y, color.RGBA{uint8(r >> 8), uint8(g >> 8), uint8(b >> 8), finalA})
					}
				}
				// Outside bounds? Leave transparent (do nothing).
			}
		}
	}

	// 7. Write Output
	out, err := os.Create(outputPath)
	if err != nil {
		panic(err)
	}
	defer out.Close()
	png.Encode(out, canvas)
	fmt.Println("SUCCESS: Correctly Standardized Icon Generated.")

	// 8. Generate Windows ICO (256x256)
	// Calculate 256x256 icon by averaging 4x4 blocks from 1024x1024 canvas
	icon256 := image.NewRGBA(image.Rect(0, 0, 256, 256))
	for y := 0; y < 256; y++ {
		for x := 0; x < 256; x++ {
			var r, g, b, a uint32
			for dy := 0; dy < 4; dy++ {
				for dx := 0; dx < 4; dx++ {
					// canvas is 1024x1024
					c := canvas.At(x*4+dx, y*4+dy)
					cr, cg, cb, ca := c.RGBA()
					r += cr
					g += cg
					b += cb
					a += ca
				}
			}
			// Average and convert to uint8
			icon256.Set(x, y, color.RGBA{uint8((r / 16) >> 8), uint8((g / 16) >> 8), uint8((b / 16) >> 8), uint8((a / 16) >> 8)})
		}
	}

	winIconDir := "build/windows"
	if err := os.MkdirAll(winIconDir, 0755); err != nil {
		panic(err)
	}

	icoPath := "build/windows/icon.ico"
	icoOut, err := os.Create(icoPath)
	if err != nil {
		panic(err)
	}
	defer icoOut.Close()

	// Encode 256x256 PNG
	buf := new(bytes.Buffer)
	if err := png.Encode(buf, icon256); err != nil {
		panic(err)
	}
	pngBytes := buf.Bytes()

	// Write ICO Header
	// Reserved (2), Type (2), Count (2)
	binary.Write(icoOut, binary.LittleEndian, uint16(0))
	binary.Write(icoOut, binary.LittleEndian, uint16(1))
	binary.Write(icoOut, binary.LittleEndian, uint16(1))

	// Write ICO Directory Entry
	// Width (1), Height (1), ColorCount (1), Reserved (1), Planes (2), BitCount (2), BytesInRes (4), ImageOffset (4)
	icoOut.Write([]byte{0, 0, 0, 0}) // 0 means 256
	binary.Write(icoOut, binary.LittleEndian, uint16(1))
	binary.Write(icoOut, binary.LittleEndian, uint16(32))
	binary.Write(icoOut, binary.LittleEndian, uint32(len(pngBytes)))
	binary.Write(icoOut, binary.LittleEndian, uint32(22)) // 6 (header) + 16 (entry) = 22

	// Write PNG Data
	icoOut.Write(pngBytes)

	fmt.Printf("SUCCESS: Generated %s\n", icoPath)

	// 9. Generate macOS ICNS (Requires macOS usually, using sips/iconutil)
	// We are on macOS (user OS is mac), so this is safe.
	fmt.Println("Generating macOS ICNS...")
	iconsetDir := "build/darwin/gtrace.iconset"
	if err := os.MkdirAll(iconsetDir, 0755); err != nil {
		panic(err)
	}
	defer os.RemoveAll(iconsetDir)

	// Sizes needed for iconset
	sizes := []int{16, 32, 64, 128, 256, 512, 1024}
	for _, s := range sizes {
		// Normal
		name := fmt.Sprintf("icon_%dx%d.png", s, s)
		cmd := exec.Command("sips", "-z", strconv.Itoa(s), strconv.Itoa(s), outputPath, "--out", filepath.Join(iconsetDir, name))
		if err := cmd.Run(); err != nil {
			fmt.Printf("Warning: Failed to generate %s: %v\n", name, err)
		}

		// Retina (@2x)
		if s < 512 { // 512x512@2x is 1024x1024
			name2x := fmt.Sprintf("icon_%dx%d@2x.png", s, s)
			s2x := s * 2
			cmd := exec.Command("sips", "-z", strconv.Itoa(s2x), strconv.Itoa(s2x), outputPath, "--out", filepath.Join(iconsetDir, name2x))
			if err := cmd.Run(); err != nil {
				fmt.Printf("Warning: Failed to generate %s: %v\n", name2x, err)
			}
		}
	}

	// 1024x1024 is technically 512@2x, usually mapped as such
	// standard `icon_512x512@2x.png` should be 1024x1024
	cmd := exec.Command("cp", outputPath, filepath.Join(iconsetDir, "icon_512x512@2x.png"))
	cmd.Run()

	// Compile to icns
	icnsPath := "build/darwin/icon.icns"
	cmd = exec.Command("iconutil", "-c", "icns", iconsetDir, "-o", icnsPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("Error running iconutil: %s\n", out)
		panic(err)
	}
	fmt.Printf("SUCCESS: Generated %s\n", icnsPath)
}
