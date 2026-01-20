package main

import (
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
)

func main() {
	width := 1024
	height := 1024

	// Create image
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Colors
	bg := color.RGBA{11, 14, 20, 255}      // #0b0e14
	fg := color.RGBA{56, 189, 248, 255}    // #38bdf8
	accent := color.RGBA{37, 99, 235, 255} // #2563eb

	// Standard macOS Icon Visual Weight:
	// The "Squircle" block usually sits at approx 82.5% of the canvas size (approx 844px for 1024px box).
	// This leaves room for the system drop shadow and bouncing animations.
	scale := 0.825
	wF := float64(width) * scale
	offset := int((float64(width) - wF) / 2) // approx 90px

	// Inner Box Coordinates
	x1, y1 := offset, offset
	x2, y2 := width-offset, height-offset

	// Fill Background (Rounded Rectangle within inner box)
	// Create a mask for rounded corners
	// Standard curvature for the 1024px canvas is ~225px, but since we scaled down our object, we scale radius too.
	// 225 * 0.825 ~= 185. Let's use 190 for smoothness.
	radius := 190
	radiusSq := radius * radius

	// Draw bg color everywhere first (software clip logic below)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			// Check if outside standard box
			if x < x1 || x >= x2 || y < y1 || y >= y2 {
				continue
			}

			// Relative coordinates to the inner box
			rx := x - x1
			ry := y - y1
			rw := x2 - x1
			rh := y2 - y1

			// Simple rounded rect math
			// Check 4 corners
			inCorner := false
			dx, dy := 0, 0

			if rx < radius && ry < radius {
				dx, dy = radius-rx, radius-ry
				inCorner = true
			} else if rx > rw-radius && ry < radius {
				dx, dy = rx-(rw-radius), radius-ry
				inCorner = true
			} else if rx < radius && ry > rh-radius {
				dx, dy = radius-rx, ry-(rh-radius) // Fixed logic
				inCorner = true
			} else if rx > rw-radius && ry > rh-radius {
				dx, dy = rx-(rw-radius), ry-(rh-radius)
				inCorner = true
			}

			if inCorner {
				if dx*dx+dy*dy <= radiusSq {
					img.Set(x, y, bg)
				}
				// else transparent
			} else {
				img.Set(x, y, bg)
			}
		}
	}

	// Helper to draw rect (clamped to our drawing area reasonably)
	fill := func(x, y, w, h int, c color.Color) {
		r := image.Rect(x, y, x+w, y+h)
		draw.Draw(img, r, &image.Uniform{c}, image.Point{}, draw.Src)
	}

	// Draw "G"
	// G Logic (Scaled to 1024 but centered)
	// Thickness: 90 (Sleek)
	// Margin: 300 (Significant padding to keep the logo nicely centered and 'small' inside the box)
	m := 300
	t := 90

	// Top Bar
	fill(m, m, width-2*m, t, fg)

	// Left Bar
	fill(m, m, t, height-2*m, fg)

	// Bottom Bar
	fill(m, height-m-t, width-2*m, t, fg)

	// Right Bottom Vertical Hook
	fill(width-m-t, height/2, t, height/2-m, fg)

	// Middle Horizontal Inset
	fill(width/2, height/2, width/2-m, t, fg)

	// Add a glowing effect/accent (simple inner rects)
	// Top Bar Accent
	fill(m+20, m+20, width-2*m-40, 20, accent)

	// Save
	f, err := os.Create("build/appicon.png")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	if err := png.Encode(f, img); err != nil {
		panic(err)
	}

	println("Generated build/appicon.png")
}
