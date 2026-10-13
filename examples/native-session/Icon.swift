// Build-time vector artwork, rendered at every macOS app-icon size.
import AppKit

let destination = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = size * scale
        let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
                                      bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                      isPlanar: false, colorSpaceName: .deviceRGB,
                                      bytesPerRow: 0, bitsPerPixel: 0)!
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
        let transform = NSAffineTransform()
        transform.scale(by: CGFloat(pixels) / 1024)
        transform.concat()
        let tile = NSBezierPath(roundedRect: NSRect(x: 100, y: 100, width: 824, height: 824),
                                xRadius: 184, yRadius: 184)
        NSGradient(starting: NSColor(srgbRed: 0.05, green: 0.24, blue: 0.32, alpha: 1),
                   ending: NSColor(srgbRed: 0.10, green: 0.64, blue: 0.64, alpha: 1))!
            .draw(in: tile, angle: 55)
        let shield = NSBezierPath()
        shield.move(to: NSPoint(x: 512, y: 770))
        shield.curve(to: NSPoint(x: 740, y: 690), controlPoint1: NSPoint(x: 590, y: 730), controlPoint2: NSPoint(x: 665, y: 704))
        shield.line(to: NSPoint(x: 728, y: 520))
        shield.curve(to: NSPoint(x: 512, y: 270), controlPoint1: NSPoint(x: 717, y: 395), controlPoint2: NSPoint(x: 610, y: 308))
        shield.curve(to: NSPoint(x: 296, y: 520), controlPoint1: NSPoint(x: 414, y: 308), controlPoint2: NSPoint(x: 307, y: 395))
        shield.line(to: NSPoint(x: 284, y: 690))
        shield.curve(to: NSPoint(x: 512, y: 770), controlPoint1: NSPoint(x: 359, y: 704), controlPoint2: NSPoint(x: 434, y: 730))
        shield.close()
        NSColor.white.withAlphaComponent(0.96).setFill()
        shield.fill()
        let mark = NSBezierPath()
        mark.move(to: NSPoint(x: 403, y: 530))
        mark.line(to: NSPoint(x: 482, y: 453))
        mark.line(to: NSPoint(x: 628, y: 610))
        mark.lineWidth = 43
        mark.lineCapStyle = .round
        mark.lineJoinStyle = .round
        NSColor(srgbRed: 0.07, green: 0.40, blue: 0.46, alpha: 1).setStroke()
        mark.stroke()
        NSGraphicsContext.restoreGraphicsState()
        let suffix = scale == 2 ? "@2x" : ""
        let file = destination.appendingPathComponent("icon_\(size)x\(size)\(suffix).png")
        try bitmap.representation(using: .png, properties: [:])!.write(to: file)
    }
}
