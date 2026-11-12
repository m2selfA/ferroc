use ferroc::icons;

fn png_size(bytes: &[u8]) -> (u32, u32) {
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(&bytes[12..16], b"IHDR");
    assert_eq!(bytes[24], 8, "8-bit channels");
    assert_eq!(bytes[25], 6, "RGBA, including transparency");
    (
        u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
        u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
    )
}

#[test]
fn png_variants_have_expected_dimensions_and_alpha_format() {
    assert_eq!(png_size(icons::PNG), (1024, 1024));
    assert_eq!(png_size(icons::PNG_32), (32, 32));
    for (size, png) in [
        (16, include_bytes!("../assets/icons/16.png").as_slice()),
        (20, include_bytes!("../assets/icons/20.png").as_slice()),
        (24, include_bytes!("../assets/icons/24.png").as_slice()),
        (32, include_bytes!("../assets/icons/32.png").as_slice()),
        (40, include_bytes!("../assets/icons/40.png").as_slice()),
        (48, include_bytes!("../assets/icons/48.png").as_slice()),
        (64, include_bytes!("../assets/icons/64.png").as_slice()),
        (128, include_bytes!("../assets/icons/128.png").as_slice()),
        (256, include_bytes!("../assets/icons/256.png").as_slice()),
        (512, include_bytes!("../assets/icons/512.png").as_slice()),
    ] {
        assert_eq!(png_size(png), (size, size));
    }
}

#[test]
fn ico_directory_and_payloads_match_the_same_png_variants() {
    let ico = icons::ICO;
    let variants = [
        (16, include_bytes!("../assets/icons/16.png").as_slice()),
        (24, include_bytes!("../assets/icons/24.png").as_slice()),
        (32, include_bytes!("../assets/icons/32.png").as_slice()),
        (48, include_bytes!("../assets/icons/48.png").as_slice()),
        (64, include_bytes!("../assets/icons/64.png").as_slice()),
        (128, include_bytes!("../assets/icons/128.png").as_slice()),
        (256, include_bytes!("../assets/icons/256.png").as_slice()),
    ];
    assert_eq!(&ico[..6], &[0, 0, 1, 0, 7, 0]);
    let mut next = 6 + 16 * variants.len();
    for (index, (size, png)) in variants.iter().enumerate() {
        let start = 6 + 16 * index;
        let dimension = if *size == 256 { 0 } else { *size as u8 };
        assert_eq!(&ico[start..start + 4], &[dimension, dimension, 0, 0]);
        assert_eq!(&ico[start + 4..start + 8], &[1, 0, 32, 0]);
        let length = u32::from_le_bytes(ico[start + 8..start + 12].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(ico[start + 12..start + 16].try_into().unwrap()) as usize;
        assert_eq!(offset, next, "ordered non-overlapping payloads");
        assert_eq!(length, png.len());
        assert_eq!(&ico[offset..offset + length], *png);
        assert_eq!(png_size(png), (*size, *size));
        next = offset + length;
    }
    assert_eq!(next, ico.len(), "no unindexed trailing payload");
}
