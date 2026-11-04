package com.example.spamdetector;

import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Advanced Quishing (QR Phishing) & Visual Payload Forensics Engine
 * Inspects decoded QR payloads for:
 * 1. Open Redirection Abuse (bit.ly, tinyurl, t.co)
 * 2. SSRF / Private IP range exploitation (RFC 1918 10.x, 192.168.x, 172.16.x, AWS metadata 169.254.169.254)
 * 3. Encoded data URI payloads (data:text/html, javascript:)
 */
@Service
public class QrCodeScannerService {

    private static final Logger log = LoggerFactory.getLogger(QrCodeScannerService.class);

    private static final Pattern PRIVATE_IP_PATTERN = Pattern.compile("(?i)^(https?://)?(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|127\\.|169\\.254\\.|localhost)");
    private static final Set<String> SHORTENER_DOMAINS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly", "ow.ly", "rebrand.ly"
    );

    public record QrScanResult(
            boolean qrFound,
            String decodedPayload,
            boolean isUrl,
            boolean isSsrfRisk,
            boolean isShortenedUrl,
            String threatWarning
    ) {}

    public QrScanResult decodeQrImage(byte[] imageBytes) {
        if (imageBytes == null || imageBytes.length == 0) {
            return new QrScanResult(false, null, false, false, false, "Empty image data");
        }

        try {
            var bufferedImage = ImageIO.read(new ByteArrayInputStream(imageBytes));
            if (bufferedImage == null) {
                return new QrScanResult(false, null, false, false, false, "Could not decode image format");
            }

            LuminanceSource source = new BufferedImageLuminanceSource(bufferedImage);
            BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));

            Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
            hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);

            Result result = new MultiFormatReader().decode(bitmap, hints);
            String text = result.getText();
            boolean isUrl = text.startsWith("http://") || text.startsWith("https://") || text.startsWith("www.");
            boolean isSsrf = false;
            boolean isShortened = false;
            StringBuilder warning = new StringBuilder();

            if (isUrl) {
                warning.append("Quishing Alert: Direct URL embedded in QR matrix. ");
                if (PRIVATE_IP_PATTERN.matcher(text).find()) {
                    isSsrf = true;
                    warning.append("CRITICAL SSRF / Intranet Attack: Target resolves to private RFC 1918 / Cloud Metadata IP! ");
                }
                try {
                    URI uri = URI.create(text.startsWith("www.") ? "http://" + text : text);
                    String host = uri.getHost();
                    if (host != null && SHORTENER_DOMAINS.contains(host.toLowerCase())) {
                        isShortened = true;
                        warning.append("Evasion Shortener Detected: Obfuscated redirect chain via ").append(host).append(". ");
                    }
                } catch (Exception ignored) {}
            } else if (text.startsWith("data:") || text.startsWith("javascript:")) {
                warning.append("High Risk: XSS / Data URI vector embedded in QR payload.");
            } else {
                warning.append("Benign Text QR Code decoded.");
            }

            return new QrScanResult(true, text, isUrl, isSsrf, isShortened, warning.toString().trim());

        } catch (NotFoundException e) {
            return new QrScanResult(false, null, false, false, false, "No QR Code found in provided image");
        } catch (Exception e) {
            log.warn("Error decoding QR code: {}", e.getMessage());
            return new QrScanResult(false, null, false, false, false, "Failed to parse image: " + e.getMessage());
        }
    }

    public QrScanResult decodeBase64Image(String base64Data) {
        if (base64Data == null || base64Data.isBlank()) {
            return new QrScanResult(false, null, false, false, false, "No image payload provided");
        }

        try {
            String clean = base64Data;
            int commaIdx = clean.indexOf(",");
            if (commaIdx >= 0) {
                clean = clean.substring(commaIdx + 1);
            }
            byte[] bytes = Base64.getDecoder().decode(clean);
            return decodeQrImage(bytes);
        } catch (Exception e) {
            return new QrScanResult(false, null, false, false, false, "Invalid Base64 image encoding: " + e.getMessage());
        }
    }
}
