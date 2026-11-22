use zeroize::Zeroizing;

use crate::Error;

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";
const JPEG: &[u8] = b"\xff\xd8";

pub(crate) fn strip(input: &[u8], mime: &str) -> Result<(Zeroizing<Vec<u8>>, Option<u8>), Error> {
    if input.starts_with(JPEG) || mime.eq_ignore_ascii_case("image/jpeg") {
        jpeg(input).ok_or(Error::Image)
    } else if input.starts_with(PNG) || mime.eq_ignore_ascii_case("image/png") {
        Ok((png(input).ok_or(Error::Image)?, None))
    } else if mime.eq_ignore_ascii_case("image/webp") {
        Ok((webp(input).ok_or(Error::Image)?, None))
    } else {
        Err(Error::Image)
    }
}

fn png(input: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut output = Zeroizing::new(PNG.to_vec());
    let mut remaining = input.strip_prefix(PNG)?;
    // Each chunk is length, type, data, CRC. Preserved chunks keep their original CRC.
    while let Some((head, _)) = remaining.split_first_chunk::<8>() {
        let len = u32::from_be_bytes(head[..4].try_into().ok()?) as usize;
        let end = len.checked_add(12)?;
        let (chunk, rest) = remaining.split_at_checked(end)?;
        let kind = &head[4..];
        if matches!(
            kind,
            b"IHDR"
                | b"PLTE"
                | b"IDAT"
                | b"IEND"
                | b"tRNS"
                | b"gAMA"
                | b"cHRM"
                | b"sRGB"
                | b"iCCP"
                | b"sBIT"
                | b"pHYs"
                | b"cICP"
                | b"acTL"
                | b"fcTL"
                | b"fdAT"
        ) {
            output.extend_from_slice(chunk);
        }
        if kind == b"IEND" {
            return (len == 0 && rest.is_empty()).then_some(output);
        }
        remaining = rest;
    }
    None
}

fn jpeg(input: &[u8]) -> Option<(Zeroizing<Vec<u8>>, Option<u8>)> {
    let mut output = Zeroizing::new(JPEG.to_vec());
    let mut cursor = JPEG.len();
    input.strip_prefix(JPEG)?;
    let mut orientation = None;
    let mut in_scan = false;
    while cursor < input.len() {
        if in_scan {
            let next = scan_end(input, cursor)?;
            output.extend_from_slice(&input[cursor..next]);
            cursor = next;
        }
        let start = cursor;
        let marker = marker(input, &mut cursor)?;
        if marker == 0xd9 {
            output.extend_from_slice(&input[start..cursor]);
            return Some((output, orientation));
        }
        if marker == 0x01 {
            output.extend_from_slice(&input[start..cursor]);
            in_scan = false;
            continue;
        }
        if matches!(marker, 0x00 | 0xd0..=0xd8) {
            return None;
        }
        let ([hi, lo], _) = input[cursor..].split_first_chunk::<2>()?;
        let length = u16::from_be_bytes([*hi, *lo]) as usize;
        let end = cursor.checked_add(length)?;
        let data = input.get(cursor + 2..end)?;
        if marker == 0xe1 && orientation.is_none() {
            orientation = data.strip_prefix(b"Exif\0\0").and_then(exif_orientation);
        }
        let icc = marker == 0xe2 && data.starts_with(b"ICC_PROFILE\0") && data.len() >= 14;
        let thumbnail = marker == 0xe0 && data.starts_with(b"JFXX\0");
        if (!matches!(marker, 0xe1..=0xef | 0xfe) && !thumbnail) || icc {
            output.extend_from_slice(&input[start..end]);
        }
        cursor = end;
        // SOS starts an entropy-coded scan. DNL can occur within one.
        in_scan = marker == 0xda || (in_scan && marker == 0xdc);
    }
    None
}

fn webp(input: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (size, contents) = input.strip_prefix(b"RIFF")?.split_first_chunk::<4>()?;
    let bytes = contents.get(..u32::from_le_bytes(*size) as usize)?;
    let mut remaining = bytes.strip_prefix(b"WEBP")?;
    let mut output = Zeroizing::new(input.get(..12)?.to_vec());
    while !remaining.is_empty() {
        let (head, _) = remaining.split_first_chunk::<8>()?;
        let len = u32::from_le_bytes(head[4..].try_into().ok()?) as usize;
        let end = 8usize.checked_add(len)?.checked_add(len % 2)?;
        let (chunk, rest) = remaining.split_at_checked(end)?;
        let kind = &head[..4];
        if !matches!(kind, b"EXIF" | b"XMP ") {
            let start = output.len();
            output.extend_from_slice(chunk);
            if kind == b"VP8X" {
                if len != 10 {
                    return None;
                }
                // Clear the EXIF and XMP bits, keeping alpha, animation and ICC.
                output[start + 8] &= !0x0c;
            }
        }
        remaining = rest;
    }
    let size = u32::try_from(output.len() - 8).ok()?;
    output[4..8].copy_from_slice(&size.to_le_bytes());
    Some(output)
}

fn marker(input: &[u8], cursor: &mut usize) -> Option<u8> {
    if input.get(*cursor) != Some(&0xff) {
        return None;
    }
    while input.get(*cursor) == Some(&0xff) {
        *cursor += 1;
    }
    let code = *input.get(*cursor)?;
    *cursor += 1;
    Some(code)
}

fn scan_end(input: &[u8], mut cursor: usize) -> Option<usize> {
    loop {
        cursor += input.get(cursor..)?.iter().position(|&byte| byte == 0xff)?;
        let start = cursor;
        if !matches!(marker(input, &mut cursor)?, 0x00 | 0xd0..=0xd7) {
            return Some(start);
        }
    }
}

fn exif_orientation(tiff: &[u8]) -> Option<u8> {
    let little = match tiff.get(..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let u16_at = |bytes: &[u8]| {
        let (bytes, _) = bytes.split_first_chunk::<2>()?;
        Some(if little {
            u16::from_le_bytes(*bytes)
        } else {
            u16::from_be_bytes(*bytes)
        })
    };
    let u32_at = |bytes: &[u8]| {
        let (bytes, _) = bytes.split_first_chunk::<4>()?;
        Some(if little {
            u32::from_le_bytes(*bytes)
        } else {
            u32::from_be_bytes(*bytes)
        })
    };
    if u16_at(tiff.get(2..)?)? != 42 {
        return None;
    }
    let offset = u32_at(tiff.get(4..)?)? as usize;
    if offset < 8 {
        return None;
    }
    let (count, entries) = tiff.get(offset..)?.split_first_chunk::<2>()?;
    let (entries, _) = entries.as_chunks::<12>();
    for entry in entries.iter().take(usize::from(u16_at(count)?)) {
        if u16_at(entry)? == 0x0112 && u16_at(&entry[2..])? == 3 && u32_at(&entry[4..])? == 1 {
            let value = u8::try_from(u16_at(&entry[8..])?).ok()?;
            return (1..=8).contains(&value).then_some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut chunk = (data.len() as u32).to_be_bytes().to_vec();
        chunk.extend_from_slice(kind);
        chunk.extend_from_slice(data);
        let mut crc = u32::MAX;
        for &byte in &chunk[4..] {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ if crc & 1 == 1 { 0xedb8_8320 } else { 0 };
            }
        }
        chunk.extend_from_slice(&(!crc).to_be_bytes());
        chunk
    }

    #[test]
    fn png_preserves_image_chunks_and_removes_all_specified_metadata() {
        let header = png_chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]);
        let pixels = png_chunk(b"IDAT", &[120, 156, 99, 96, 0, 0, 0, 2, 0, 1]);
        let end = png_chunk(b"IEND", &[]);
        let mut fixture = [PNG, &header].concat();
        for kind in [b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME", b"caBX"] {
            fixture.extend(png_chunk(kind, b"test data"));
        }
        fixture.extend_from_slice(&pixels);
        fixture.extend_from_slice(&end);
        let (clean, orientation) = strip(&fixture, "image/png").unwrap();
        assert_eq!(clean.as_slice(), [PNG, &header, &pixels, &end].concat());
        assert_eq!(orientation, None);
        assert!(strip(&fixture[..fixture.len() - 1], "image/png").is_err());
    }

    fn jpeg_segment(code: u8, data: &[u8]) -> Vec<u8> {
        let mut segment = vec![0xff, code];
        segment.extend_from_slice(&((data.len() as u16) + 2).to_be_bytes());
        segment.extend_from_slice(data);
        segment
    }

    #[test]
    fn jpeg_preserves_scan_and_icc_and_reads_orientation() {
        let mut fixture = JPEG.to_vec();
        let mut expected = JPEG.to_vec();
        let app0 = jpeg_segment(0xe0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
        let exif = jpeg_segment(
            0xe1,
            b"Exif\0\0II\x2a\0\x08\0\0\0\x01\0\x12\x01\x03\0\x01\0\0\0\x06\0\0\0\0\0\0\0",
        );
        let icc = jpeg_segment(0xe2, b"ICC_PROFILE\0\x01\x01profile");
        fixture.extend(&app0);
        fixture.extend(jpeg_segment(0xe0, b"JFXX\0thumbnail"));
        fixture.extend(exif);
        fixture.extend(jpeg_segment(0xe2, b"other APP2"));
        fixture.extend(&icc);
        fixture.extend(jpeg_segment(0xef, b"APP15"));
        expected.extend(app0);
        expected.extend(icc);

        // An 8-bit baseline grayscale image with one all-zero DCT block.
        let mut quantization = vec![0];
        quantization.extend([1; 64]);
        let counts = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let huffman = [&[0], counts.as_slice(), &[0], &[0x10], &counts, &[0]].concat();
        let encoded = [
            jpeg_segment(0xdb, &quantization),
            jpeg_segment(0xc0, &[8, 0, 1, 0, 1, 1, 1, 0x11, 0]),
            jpeg_segment(0xc4, &huffman),
            jpeg_segment(0xda, &[1, 1, 0, 0, 63, 0]),
            vec![0x3f],
        ]
        .concat();
        fixture.extend(&encoded);
        fixture.extend(jpeg_segment(0xfe, b"comment after scan"));
        fixture.extend([0xff, 0xd9]);
        expected.extend(encoded);
        expected.extend([0xff, 0xd9]);
        let (clean, orientation) = strip(&fixture, "image/jpeg").unwrap();
        assert_eq!(clean.as_slice(), expected);
        assert_eq!(orientation, Some(6));
        assert!(strip(&fixture[..fixture.len() - 1], "image/jpeg").is_err());
        fixture.extend(b"trailing metadata");
        assert_eq!(
            strip(&fixture, "image/jpeg").unwrap().0.as_slice(),
            expected
        );
        assert_eq!(
            exif_orientation(b"MM\0\x2a\0\0\0\x08\0\x01\x01\x12\0\x03\0\0\0\x01\0\x08\0\0"),
            Some(8)
        );
    }

    #[test]
    fn webp_removes_metadata_and_preserves_other_flags() {
        fn container(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
            let mut data = b"WEBP".to_vec();
            for (kind, bytes) in chunks {
                data.extend(*kind);
                data.extend((bytes.len() as u32).to_le_bytes());
                data.extend(*bytes);
                if bytes.len() % 2 != 0 {
                    data.push(0);
                }
            }
            [b"RIFF", (data.len() as u32).to_le_bytes().as_slice(), &data].concat()
        }
        let input = container(&[
            (b"VP8X", &[0x3e, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (b"EXIF", b"metadata"),
            (b"XMP ", b"odd"),
            (b"ANIM", &[0; 6]),
        ]);
        let clean = container(&[
            (b"VP8X", &[0x32, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (b"ANIM", &[0; 6]),
        ]);
        assert_eq!(strip(&input, "image/webp").unwrap().0.as_slice(), clean);
        assert!(strip(&input[..input.len() - 1], "image/webp").is_err());
    }

    #[test]
    fn scan_skips_stuffed_bytes_and_restart_markers() {
        assert_eq!(scan_end(b"\x10\xff\0\x03\xff\xd7\xff\xff\xda", 0), Some(6));
    }
}
