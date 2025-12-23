//! Memory benchmark to measure parsing memory usage independent of DuckDB

use otel_metrics::common::read_binpb_file;
use otel_metrics::metrics::parse_metrics;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

// Custom allocator to track memory usage
struct TrackingAllocator;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size();
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let current = ALLOCATED.fetch_add(size, Ordering::SeqCst) + size;
            PEAK.fetch_max(current, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        ALLOCATED.fetch_sub(layout.size(), Ordering::SeqCst);
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let old_size = layout.size();
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            if new_size > old_size {
                let current = ALLOCATED.fetch_add(new_size - old_size, Ordering::SeqCst) + (new_size - old_size);
                PEAK.fetch_max(current, Ordering::SeqCst);
            } else {
                ALLOCATED.fetch_sub(old_size - new_size, Ordering::SeqCst);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static GLOBAL: TrackingAllocator = TrackingAllocator;

fn format_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} bytes", bytes)
    }
}

fn main() {
    let files: Vec<String> = std::fs::read_dir("testdata")
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|x| x == "gz").unwrap_or(false))
        .map(|e| e.path().to_string_lossy().to_string())
        .collect();

    println!("=== Memory Benchmark ===\n");
    println!("Files to process: {}", files.len());

    // Reset counters
    ALLOCATED.store(0, Ordering::SeqCst);
    PEAK.store(0, Ordering::SeqCst);

    let baseline = ALLOCATED.load(Ordering::SeqCst);
    println!("Baseline memory: {}", format_bytes(baseline));

    // Phase 1: Read all files into memory (decompressed)
    println!("\n--- Phase 1: Reading files ---");
    let mut file_data: Vec<Vec<u8>> = Vec::new();
    let mut total_bytes = 0usize;

    for file_path in &files {
        let data = read_binpb_file(file_path).expect("Failed to read file");
        total_bytes += data.len();
        file_data.push(data);
    }

    let after_read = ALLOCATED.load(Ordering::SeqCst);
    let peak_after_read = PEAK.load(Ordering::SeqCst);
    println!("Total uncompressed data: {}", format_bytes(total_bytes));
    println!("Memory after reading: {}", format_bytes(after_read));
    println!("Peak memory: {}", format_bytes(peak_after_read));

    // Phase 2: Parse all files
    println!("\n--- Phase 2: Parsing metrics ---");
    let mut all_rows = Vec::new();
    let mut total_rows = 0usize;

    for data in &file_data {
        let rows = parse_metrics(data, "benchmark-customer").expect("Failed to parse");
        total_rows += rows.len();
        all_rows.extend(rows);
    }

    let after_parse = ALLOCATED.load(Ordering::SeqCst);
    let peak_after_parse = PEAK.load(Ordering::SeqCst);
    println!("Total rows parsed: {}", total_rows);
    println!("Memory after parsing: {}", format_bytes(after_parse));
    println!("Peak memory: {}", format_bytes(peak_after_parse));

    // Calculate memory per row
    let row_memory = after_parse.saturating_sub(after_read);
    let per_row = if total_rows > 0 { row_memory / total_rows } else { 0 };
    println!("Memory for rows: {} ({} bytes/row avg)", format_bytes(row_memory), per_row);

    // Phase 3: Drop file data (simulate streaming - we wouldn't keep raw bytes)
    println!("\n--- Phase 3: Drop raw file data ---");
    drop(file_data);

    let after_drop = ALLOCATED.load(Ordering::SeqCst);
    println!("Memory after dropping raw data: {}", format_bytes(after_drop));
    println!("Memory saved by streaming: {}", format_bytes(total_bytes));

    // Summary
    println!("\n=== Summary ===");
    println!("Peak memory (our code): {}", format_bytes(peak_after_parse));
    println!("Final memory holding {} rows: {}", total_rows, format_bytes(after_drop));
    println!("Bytes per row (parsed): {}", per_row);
    println!("\nFor comparison, DuckDB total was ~900 MB");
    println!("Our code peak: {} ({:.1}% of total)",
             format_bytes(peak_after_parse),
             100.0 * peak_after_parse as f64 / 900_000_000.0);
}
