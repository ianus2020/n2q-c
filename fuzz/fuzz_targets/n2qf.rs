#![no_main]
use libfuzzer_sys::fuzz_target;
use n2q_c_ref::{file, modes_ext};
fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let parsed = file::parse(&[0; 16], data);
    if let Ok(chunks) = parsed {
        assert!(chunks.iter().all(|c| !c.is_empty() && c.len() <= 65536));
        assert!(chunks.iter().map(Vec::len).sum::<usize>() <= data.len());
        assert_eq!(
            modes_ext::seek_chunk(&[0; 16], data, 0),
            chunks.first().cloned()
        );
    } else {
        assert!(modes_ext::seek_chunk(&[0; 16], data, 0).is_none());
    }
});
