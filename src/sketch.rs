// Copyright 2025 CardinalHQ, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! DDSketch implementation and histogram conversion utilities.
//!
//! This module provides:
//! - DDSketch data structure with DataDog-compatible wire format
//! - Conversion from OTEL Histogram to DDSketch
//! - Conversion from OTEL ExponentialHistogram to DDSketch
//! - Conversion from OTEL Summary to DDSketch
//! - Rollup statistics extraction

use std::io::{Read, Write};

// ============================================================================
// Constants
// ============================================================================

/// Default relative accuracy for DDSketch (1%)
pub const DEFAULT_RELATIVE_ACCURACY: f64 = 0.01;

/// Maximum samples when interpolating from summary quantiles
const MAX_SAMPLES: usize = 2048;

// ============================================================================
// Varint Encoding (DataDog format)
// ============================================================================

fn encode_uvarint64<W: Write>(w: &mut W, mut value: u64) -> std::io::Result<()> {
    while value >= 0x80 {
        w.write_all(&[(value as u8) | 0x80])?;
        value >>= 7;
    }
    w.write_all(&[value as u8])
}

fn decode_uvarint64<R: Read>(r: &mut R) -> std::io::Result<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    let mut buf = [0u8; 1];

    loop {
        r.read_exact(&mut buf)?;
        let byte = buf[0];
        result |= ((byte & 0x7F) as u64) << shift;
        if byte < 0x80 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "varint overflow",
            ));
        }
    }
    Ok(result)
}

fn encode_varint64<W: Write>(w: &mut W, value: i64) -> std::io::Result<()> {
    let zigzag = ((value << 1) ^ (value >> 63)) as u64;
    encode_uvarint64(w, zigzag)
}

fn decode_varint64<R: Read>(r: &mut R) -> std::io::Result<i64> {
    let zigzag = decode_uvarint64(r)?;
    Ok(((zigzag >> 1) as i64) ^ (-((zigzag & 1) as i64)))
}

const VARFLOAT64_ROTATE: u32 = 6;
const MAX_VAR_LEN_64: usize = 9;

fn encode_varfloat64<W: Write>(w: &mut W, v: f64) -> std::io::Result<()> {
    let float_bits_1 = 1.0f64.to_bits();
    let mut x = ((v + 1.0).to_bits().wrapping_sub(float_bits_1)).rotate_left(VARFLOAT64_ROTATE);

    for _ in 0..MAX_VAR_LEN_64 - 1 {
        let n = (x >> (64 - 7)) as u8;
        x <<= 7;
        if x == 0 {
            w.write_all(&[n])?;
            return Ok(());
        }
        w.write_all(&[n | 0x80])?;
    }
    let n = (x >> (8 * 7)) as u8;
    w.write_all(&[n])?;
    Ok(())
}

fn decode_varfloat64<R: Read>(r: &mut R) -> std::io::Result<f64> {
    let mut x: u64 = 0;
    let mut s: u32 = 64 - 7;
    let mut buf = [0u8; 1];

    for i in 0..MAX_VAR_LEN_64 {
        r.read_exact(&mut buf)?;
        let n = buf[0];

        if i == MAX_VAR_LEN_64 - 1 {
            x |= n as u64;
            break;
        }

        if n < 0x80 {
            x |= (n as u64) << s;
            break;
        }

        x |= ((n & 0x7F) as u64) << s;
        s = s.saturating_sub(7);
    }

    let float_bits_1 = 1.0f64.to_bits();
    let bits = x.rotate_right(VARFLOAT64_ROTATE).wrapping_add(float_bits_1);
    Ok(f64::from_bits(bits) - 1.0)
}

fn encode_float64_le<W: Write>(w: &mut W, value: f64) -> std::io::Result<()> {
    w.write_all(&value.to_le_bytes())
}

fn decode_float64_le<R: Read>(r: &mut R) -> std::io::Result<f64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(f64::from_le_bytes(buf))
}

// ============================================================================
// Flag Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
enum FlagType {
    SketchFeatures = 0b00,
    PositiveStore = 0b01,
    IndexMapping = 0b10,
    NegativeStore = 0b11,
}

impl FlagType {
    fn from_byte(b: u8) -> Self {
        match b & 0b11 {
            0b00 => FlagType::SketchFeatures,
            0b01 => FlagType::PositiveStore,
            0b10 => FlagType::IndexMapping,
            0b11 => FlagType::NegativeStore,
            _ => unreachable!(),
        }
    }
}

fn make_flag(flag_type: FlagType, subflag: u8) -> u8 {
    (subflag << 2) | (flag_type as u8)
}

fn get_subflag(flag: u8) -> u8 {
    flag >> 2
}

// ============================================================================
// DDSketch Structure
// ============================================================================

/// DDSketch data structure with DataDog-compatible format.
#[derive(Debug, Clone)]
pub struct DDSketch {
    /// Gamma for logarithmic mapping
    pub gamma: f64,
    /// Index offset for the mapping
    pub index_offset: f64,
    /// Positive value bins: (index, count)
    pub positive_bins: Vec<(i32, f64)>,
    /// Negative value bins: (index, count)
    pub negative_bins: Vec<(i32, f64)>,
    /// Count of zero values
    pub zero_count: f64,
    /// Sum of all values
    pub sum: f64,
    /// Total count
    pub count: f64,
    /// Minimum value
    pub min: f64,
    /// Maximum value
    pub max: f64,
}

impl Default for DDSketch {
    fn default() -> Self {
        Self::new(DEFAULT_RELATIVE_ACCURACY)
    }
}

impl DDSketch {
    /// Create new sketch with given relative accuracy.
    pub fn new(relative_accuracy: f64) -> Self {
        DDSketch {
            gamma: 1.0 + 2.0 * relative_accuracy / (1.0 - relative_accuracy),
            index_offset: 0.0,
            positive_bins: Vec::new(),
            negative_bins: Vec::new(),
            zero_count: 0.0,
            sum: 0.0,
            count: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
        }
    }

    /// Add a value to the sketch.
    pub fn add(&mut self, value: f64) {
        self.add_with_count(value, 1.0);
    }

    /// Add a value with a specific count.
    pub fn add_with_count(&mut self, value: f64, count: f64) {
        if count <= 0.0 || !value.is_finite() {
            return;
        }

        self.count += count;
        self.sum += value * count;

        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }

        if value == 0.0 {
            self.zero_count += count;
        } else if value > 0.0 {
            let index = self.value_to_bin(value);
            Self::add_to_bin(&mut self.positive_bins, index, count);
        } else {
            let index = self.value_to_bin(-value);
            Self::add_to_bin(&mut self.negative_bins, index, count);
        }
    }

    fn value_to_bin(&self, value: f64) -> i32 {
        let log_gamma = self.gamma.ln();
        (value.ln() / log_gamma + self.index_offset).ceil() as i32
    }

    fn add_to_bin(bins: &mut Vec<(i32, f64)>, index: i32, count: f64) {
        match bins.binary_search_by_key(&index, |(i, _)| *i) {
            Ok(pos) => bins[pos].1 += count,
            Err(pos) => bins.insert(pos, (index, count)),
        }
    }

    fn bin_to_value(&self, index: i32) -> f64 {
        let adjusted = index as f64 - self.index_offset;
        let lower_bound = self.gamma.powf(adjusted);
        let relative_accuracy = 1.0 - 2.0 / (1.0 + self.gamma);
        lower_bound * (1.0 + relative_accuracy)
    }

    /// Get quantile value.
    pub fn quantile(&self, q: f64) -> Option<f64> {
        if self.count == 0.0 || q < 0.0 || q > 1.0 {
            return None;
        }

        let rank = q * (self.count - 1.0);
        let negative_count: f64 = self.negative_bins.iter().map(|(_, c)| c).sum();

        if rank < negative_count {
            let neg_rank = negative_count - 1.0 - rank;
            return Some(-self.key_at_rank(&self.negative_bins, neg_rank));
        }

        if rank < negative_count + self.zero_count {
            return Some(0.0);
        }

        let pos_rank = rank - self.zero_count - negative_count;
        Some(self.key_at_rank(&self.positive_bins, pos_rank))
    }

    fn key_at_rank(&self, bins: &[(i32, f64)], rank: f64) -> f64 {
        let rank = if rank < 0.0 { 0.0 } else { rank };
        let mut cumulative = 0.0;

        for (index, count) in bins {
            cumulative += count;
            if cumulative > rank {
                return self.bin_to_value(*index);
            }
        }

        bins.last()
            .map(|(idx, _)| self.bin_to_value(*idx))
            .unwrap_or(0.0)
    }

    /// Get the average value.
    pub fn avg(&self) -> Option<f64> {
        if self.count > 0.0 {
            Some(self.sum / self.count)
        } else {
            None
        }
    }

    /// Get the minimum value.
    pub fn get_min(&self) -> Option<f64> {
        if self.count > 0.0 && self.min.is_finite() {
            Some(self.min)
        } else {
            None
        }
    }

    /// Get the maximum value.
    pub fn get_max(&self) -> Option<f64> {
        if self.count > 0.0 && self.max.is_finite() {
            Some(self.max)
        } else {
            None
        }
    }

    /// Encode to DataDog wire format.
    pub fn encode(&self) -> Result<Vec<u8>, std::io::Error> {
        let mut buf = Vec::new();
        self.encode_to(&mut buf)?;
        Ok(buf)
    }

    /// Encode to a writer.
    pub fn encode_to<W: Write>(&self, w: &mut W) -> Result<(), std::io::Error> {
        // Index mapping
        let flag = make_flag(FlagType::IndexMapping, 0); // LogarithmicMapping
        w.write_all(&[flag])?;
        encode_float64_le(w, self.gamma)?;
        encode_float64_le(w, self.index_offset)?;

        // Positive store
        if !self.positive_bins.is_empty() {
            self.encode_store(w, FlagType::PositiveStore, &self.positive_bins)?;
        }

        // Negative store
        if !self.negative_bins.is_empty() {
            self.encode_store(w, FlagType::NegativeStore, &self.negative_bins)?;
        }

        // Zero count
        if self.zero_count > 0.0 {
            let flag = make_flag(FlagType::SketchFeatures, 1); // ZeroCount
            w.write_all(&[flag])?;
            encode_varfloat64(w, self.zero_count)?;
        }

        Ok(())
    }

    fn encode_store<W: Write>(
        &self,
        w: &mut W,
        flag_type: FlagType,
        bins: &[(i32, f64)],
    ) -> Result<(), std::io::Error> {
        let flag = make_flag(flag_type, 1); // IndexDeltasAndCounts
        w.write_all(&[flag])?;
        encode_uvarint64(w, bins.len() as u64)?;

        let mut prev_index: i32 = 0;
        for (index, count) in bins {
            let delta = *index - prev_index;
            encode_varint64(w, delta as i64)?;
            encode_varfloat64(w, *count)?;
            prev_index = *index;
        }
        Ok(())
    }

    /// Decode from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, std::io::Error> {
        let mut cursor = std::io::Cursor::new(data);
        Self::decode_from(&mut cursor)
    }

    /// Decode from a reader.
    pub fn decode_from<R: Read>(r: &mut R) -> Result<Self, std::io::Error> {
        let mut sketch = DDSketch::default();
        let mut buf = [0u8; 1];
        let mut has_explicit_count = false;
        let mut has_explicit_sum = false;

        loop {
            match r.read_exact(&mut buf) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }

            let flag = buf[0];
            let flag_type = FlagType::from_byte(flag);
            let subflag = get_subflag(flag);

            match flag_type {
                FlagType::IndexMapping => {
                    sketch.gamma = decode_float64_le(r)?;
                    sketch.index_offset = decode_float64_le(r)?;
                }
                FlagType::PositiveStore => {
                    sketch.positive_bins = sketch.decode_store(r, subflag)?;
                }
                FlagType::NegativeStore => {
                    sketch.negative_bins = sketch.decode_store(r, subflag)?;
                }
                FlagType::SketchFeatures => {
                    match subflag {
                        1 => sketch.zero_count = decode_varfloat64(r)?,
                        0x21 => {
                            has_explicit_sum = true;
                            sketch.sum = decode_float64_le(r)?;
                        }
                        0x22 => sketch.min = decode_float64_le(r)?,
                        0x23 => sketch.max = decode_float64_le(r)?,
                        0x28 => {
                            has_explicit_count = true;
                            sketch.count = decode_varfloat64(r)?;
                        }
                        _ => {}
                    }
                }
            }
        }

        // Compute from bins if not explicit
        if !has_explicit_count {
            sketch.count = sketch.compute_count_from_bins();
        }
        if !has_explicit_sum {
            sketch.sum = sketch.compute_sum_from_bins();
        }
        if !sketch.min.is_finite() || !sketch.max.is_finite() {
            sketch.compute_min_max_from_bins();
        }

        Ok(sketch)
    }

    fn decode_store<R: Read>(&self, r: &mut R, subflag: u8) -> Result<Vec<(i32, f64)>, std::io::Error> {
        match subflag {
            1 => {
                // IndexDeltasAndCounts
                let num_bins = decode_uvarint64(r)? as usize;
                let mut bins = Vec::with_capacity(num_bins);
                let mut prev_index: i32 = 0;

                for _ in 0..num_bins {
                    let delta = decode_varint64(r)? as i32;
                    let index = prev_index + delta;
                    let count = decode_varfloat64(r)?;
                    bins.push((index, count));
                    prev_index = index;
                }
                Ok(bins)
            }
            2 => {
                // IndexDeltas
                let num_bins = decode_uvarint64(r)? as usize;
                let mut bins = Vec::with_capacity(num_bins);
                let mut prev_index: i32 = 0;

                for _ in 0..num_bins {
                    let delta = decode_varint64(r)? as i32;
                    let index = prev_index + delta;
                    bins.push((index, 1.0));
                    prev_index = index;
                }
                Ok(bins)
            }
            3 => {
                // ContiguousCounts
                let num_bins = decode_uvarint64(r)? as usize;
                let start_index = decode_varint64(r)? as i32;
                let index_delta = decode_varint64(r)? as i32;
                let mut bins = Vec::with_capacity(num_bins);

                let mut index = start_index;
                for _ in 0..num_bins {
                    let count = decode_varfloat64(r)?;
                    bins.push((index, count));
                    index += index_delta;
                }
                Ok(bins)
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown bin encoding subflag: {}", subflag),
            )),
        }
    }

    fn compute_count_from_bins(&self) -> f64 {
        let pos: f64 = self.positive_bins.iter().map(|(_, c)| c).sum();
        let neg: f64 = self.negative_bins.iter().map(|(_, c)| c).sum();
        pos + neg + self.zero_count
    }

    fn compute_sum_from_bins(&self) -> f64 {
        let mut sum = 0.0;
        for (index, count) in &self.positive_bins {
            sum += self.bin_to_value(*index) * count;
        }
        for (index, count) in &self.negative_bins {
            sum -= self.bin_to_value(*index) * count;
        }
        sum
    }

    fn compute_min_max_from_bins(&mut self) {
        let mut min = f64::INFINITY;
        let mut max = f64::NEG_INFINITY;

        for (index, count) in &self.negative_bins {
            if *count > 0.0 {
                let value = -self.bin_to_value(*index);
                min = min.min(value);
                max = max.max(value);
            }
        }

        if self.zero_count > 0.0 {
            min = min.min(0.0);
            max = max.max(0.0);
        }

        for (index, count) in &self.positive_bins {
            if *count > 0.0 {
                let value = self.bin_to_value(*index);
                min = min.min(value);
                max = max.max(value);
            }
        }

        if min.is_finite() {
            self.min = min;
        }
        if max.is_finite() {
            self.max = max;
        }
    }
}

// ============================================================================
// Rollup Statistics
// ============================================================================

/// Statistics extracted from a DDSketch for storage.
#[derive(Debug, Clone, Default)]
pub struct RollupStats {
    pub avg: f64,
    pub count: f64,
    pub min: f64,
    pub max: f64,
    pub sum: f64,
    pub p25: f64,
    pub p50: f64,
    pub p75: f64,
    pub p90: f64,
    pub p95: f64,
    pub p99: f64,
}

impl RollupStats {
    /// Extract rollup statistics from a DDSketch.
    pub fn from_sketch(sketch: &DDSketch) -> Self {
        RollupStats {
            avg: sketch.avg().unwrap_or(0.0),
            count: sketch.count,
            min: sketch.get_min().unwrap_or(0.0),
            max: sketch.get_max().unwrap_or(0.0),
            sum: sketch.sum,
            p25: sketch.quantile(0.25).unwrap_or(0.0),
            p50: sketch.quantile(0.50).unwrap_or(0.0),
            p75: sketch.quantile(0.75).unwrap_or(0.0),
            p90: sketch.quantile(0.90).unwrap_or(0.0),
            p95: sketch.quantile(0.95).unwrap_or(0.0),
            p99: sketch.quantile(0.99).unwrap_or(0.0),
        }
    }
}

// ============================================================================
// Histogram Conversion
// ============================================================================

/// OTEL Histogram bucket data.
#[derive(Debug)]
pub struct HistogramBucket {
    pub upper_bound: f64,
    pub count: u64,
}

/// Convert OTEL Histogram buckets to DDSketch.
///
/// This implements the "reps" algorithm from the Go implementation:
/// for each bucket, we add representative values based on the bucket count.
pub fn histogram_to_sketch(
    buckets: &[HistogramBucket],
    sum: Option<f64>,
    count: u64,
) -> DDSketch {
    let mut sketch = DDSketch::new(DEFAULT_RELATIVE_ACCURACY);

    if buckets.is_empty() || count == 0 {
        return sketch;
    }

    let mut prev_bound = 0.0;
    let mut prev_count = 0u64;

    for bucket in buckets {
        let bucket_count = bucket.count.saturating_sub(prev_count);
        if bucket_count == 0 {
            prev_bound = bucket.upper_bound;
            prev_count = bucket.count;
            continue;
        }

        let upper = bucket.upper_bound;
        let lower = prev_bound;

        // Skip if bounds are invalid
        if !upper.is_finite() || upper <= 0.0 {
            prev_bound = bucket.upper_bound;
            prev_count = bucket.count;
            continue;
        }

        // Use geometric mean as representative value for the bucket
        let rep = if lower <= 0.0 {
            upper / 2.0
        } else {
            (lower * upper).sqrt()
        };

        sketch.add_with_count(rep, bucket_count as f64);

        prev_bound = bucket.upper_bound;
        prev_count = bucket.count;
    }

    // Override sum if provided
    if let Some(s) = sum {
        sketch.sum = s;
    }

    sketch
}

// ============================================================================
// Exponential Histogram Conversion
// ============================================================================

/// OTEL Exponential Histogram bucket data.
#[derive(Debug)]
pub struct ExponentialHistogramBuckets {
    pub offset: i32,
    pub bucket_counts: Vec<u64>,
}

/// Convert OTEL ExponentialHistogram to DDSketch.
///
/// Exponential histograms use a base of 2^(2^-scale).
/// Bucket i represents values in range [base^(offset+i), base^(offset+i+1)).
pub fn exponential_histogram_to_sketch(
    scale: i32,
    positive: Option<&ExponentialHistogramBuckets>,
    negative: Option<&ExponentialHistogramBuckets>,
    zero_count: u64,
    sum: Option<f64>,
    min: Option<f64>,
    max: Option<f64>,
) -> DDSketch {
    let mut sketch = DDSketch::new(DEFAULT_RELATIVE_ACCURACY);

    // base = 2^(2^-scale)
    let base = 2.0f64.powf(2.0f64.powi(-scale));

    // Add positive buckets
    if let Some(pos) = positive {
        for (i, &count) in pos.bucket_counts.iter().enumerate() {
            if count == 0 {
                continue;
            }
            let bucket_index = pos.offset + i as i32;
            // Lower bound: base^bucket_index, Upper bound: base^(bucket_index+1)
            let lower = base.powi(bucket_index);
            let upper = base.powi(bucket_index + 1);
            let rep = (lower * upper).sqrt(); // geometric mean
            sketch.add_with_count(rep, count as f64);
        }
    }

    // Add negative buckets (same structure, but values are negative)
    if let Some(neg) = negative {
        for (i, &count) in neg.bucket_counts.iter().enumerate() {
            if count == 0 {
                continue;
            }
            let bucket_index = neg.offset + i as i32;
            let lower = base.powi(bucket_index);
            let upper = base.powi(bucket_index + 1);
            let rep = -((lower * upper).sqrt()); // negative value
            sketch.add_with_count(rep, count as f64);
        }
    }

    // Add zero count
    if zero_count > 0 {
        sketch.add_with_count(0.0, zero_count as f64);
    }

    // Override with explicit values if provided
    if let Some(s) = sum {
        sketch.sum = s;
    }
    if let Some(m) = min {
        sketch.min = m;
    }
    if let Some(m) = max {
        sketch.max = m;
    }

    sketch
}

// ============================================================================
// Summary Conversion
// ============================================================================

/// OTEL Summary quantile value.
#[derive(Debug, Clone)]
pub struct SummaryQuantile {
    pub quantile: f64,
    pub value: f64,
}

/// Convert OTEL Summary to DDSketch.
///
/// This interpolates between quantile values to reconstruct a distribution.
/// Uses log-linear interpolation for better handling of exponential distributions.
pub fn summary_to_sketch(
    quantiles: &[SummaryQuantile],
    count: u64,
    sum: f64,
) -> DDSketch {
    let mut sketch = DDSketch::new(DEFAULT_RELATIVE_ACCURACY);

    if quantiles.is_empty() || count == 0 {
        return sketch;
    }

    // Filter valid quantiles and sort by quantile value
    let mut valid_qs: Vec<(f64, f64)> = quantiles
        .iter()
        .filter(|q| {
            q.value.is_finite() && !q.value.is_nan() && q.quantile >= 0.0 && q.quantile <= 1.0
        })
        .map(|q| {
            let q_clamped = q.quantile.clamp(0.0, 1.0);
            (q_clamped, q.value)
        })
        .collect();

    if valid_qs.is_empty() {
        return sketch;
    }

    // Remove duplicates (keep first)
    valid_qs.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
    valid_qs.dedup_by(|a, b| (a.0 - b.0).abs() < 1e-10);

    // Extrapolate endpoints if needed
    if valid_qs[0].0 > 0.0 {
        let (q1, v1) = valid_qs[0];
        let v0 = if valid_qs.len() > 1 {
            let (q2, v2) = valid_qs[1];
            interpolate_value(0.0, q1, q2, v1, v2)
        } else {
            v1 * 0.5 // Rough estimate
        };
        valid_qs.insert(0, (0.0, v0));
    }

    if valid_qs.last().unwrap().0 < 1.0 {
        let n = valid_qs.len();
        let (qn, vn) = valid_qs[n - 1];
        let v1 = if n > 1 {
            let (qn1, vn1) = valid_qs[n - 2];
            interpolate_value(1.0, qn1, qn, vn1, vn)
        } else {
            vn * 1.5 // Rough estimate
        };
        valid_qs.push((1.0, v1));
    }

    // Sample from the distribution
    let samples = MAX_SAMPLES.min(count as usize);
    for i in 0..samples {
        let q = (i as f64 + 0.5) / samples as f64;
        let value = interpolate_at_quantile(&valid_qs, q);
        sketch.add(value);
    }

    // Override sum with actual value
    sketch.sum = sum;

    sketch
}

/// Interpolate value at a given quantile using log-linear interpolation.
fn interpolate_at_quantile(qs: &[(f64, f64)], target_q: f64) -> f64 {
    // Find the surrounding quantiles
    let mut i = 0;
    while i < qs.len() - 1 && qs[i + 1].0 < target_q {
        i += 1;
    }

    if i >= qs.len() - 1 {
        return qs.last().unwrap().1;
    }

    let (q1, v1) = qs[i];
    let (q2, v2) = qs[i + 1];

    interpolate_value(target_q, q1, q2, v1, v2)
}

/// Log-linear interpolation between two points.
fn interpolate_value(target_q: f64, q1: f64, q2: f64, v1: f64, v2: f64) -> f64 {
    if (q2 - q1).abs() < 1e-10 {
        return v1;
    }

    let t = (target_q - q1) / (q2 - q1);

    // Use log interpolation if both values are positive
    if v1 > 0.0 && v2 > 0.0 {
        let log_v1 = v1.ln();
        let log_v2 = v2.ln();
        (log_v1 + t * (log_v2 - log_v1)).exp()
    } else {
        // Linear interpolation for mixed signs or zeros
        v1 + t * (v2 - v1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sketch_basic() {
        let mut sketch = DDSketch::new(0.01);
        for i in 1..=100 {
            sketch.add(i as f64);
        }

        assert_eq!(sketch.count, 100.0);
        assert_eq!(sketch.sum, 5050.0);
        assert_eq!(sketch.min, 1.0);
        assert_eq!(sketch.max, 100.0);
    }

    #[test]
    fn test_sketch_quantiles() {
        let mut sketch = DDSketch::new(0.01);
        for i in 1..=100 {
            sketch.add(i as f64);
        }

        let p50 = sketch.quantile(0.50).unwrap();
        assert!(p50 >= 48.0 && p50 <= 52.0, "p50 = {}", p50);

        let p99 = sketch.quantile(0.99).unwrap();
        assert!(p99 >= 97.0 && p99 <= 103.0, "p99 = {}", p99);
    }

    #[test]
    fn test_sketch_encode_decode() {
        let mut sketch = DDSketch::new(0.01);
        for i in 1..=100 {
            sketch.add(i as f64);
        }

        let bytes = sketch.encode().unwrap();
        let decoded = DDSketch::decode(&bytes).unwrap();

        assert_eq!(sketch.count, decoded.count);
        let rel_err = (sketch.sum - decoded.sum).abs() / sketch.sum;
        assert!(rel_err < 0.03, "sum error: {}", rel_err);
    }

    #[test]
    fn test_rollup_stats() {
        let mut sketch = DDSketch::new(0.01);
        for i in 1..=100 {
            sketch.add(i as f64);
        }

        let stats = RollupStats::from_sketch(&sketch);
        assert_eq!(stats.count, 100.0);
        assert_eq!(stats.sum, 5050.0);
        assert_eq!(stats.min, 1.0);
        assert_eq!(stats.max, 100.0);
        assert!((stats.avg - 50.5).abs() < 0.01);
    }

    #[test]
    fn test_histogram_to_sketch() {
        let buckets = vec![
            HistogramBucket { upper_bound: 10.0, count: 5 },
            HistogramBucket { upper_bound: 50.0, count: 15 },
            HistogramBucket { upper_bound: 100.0, count: 20 },
        ];

        let sketch = histogram_to_sketch(&buckets, Some(1000.0), 20);
        assert_eq!(sketch.count, 20.0);
        assert_eq!(sketch.sum, 1000.0);
    }

    #[test]
    fn test_exponential_histogram_to_sketch() {
        let positive = ExponentialHistogramBuckets {
            offset: 0,
            bucket_counts: vec![5, 10, 15],
        };

        let sketch = exponential_histogram_to_sketch(
            0, // scale
            Some(&positive),
            None,
            0,
            Some(500.0),
            Some(1.0),
            Some(100.0),
        );

        assert_eq!(sketch.count, 30.0);
        assert_eq!(sketch.sum, 500.0);
        assert_eq!(sketch.min, 1.0);
        assert_eq!(sketch.max, 100.0);
    }

    #[test]
    fn test_summary_to_sketch_basic() {
        let quantiles = vec![
            SummaryQuantile { quantile: 0.5, value: 50.0 },
            SummaryQuantile { quantile: 0.9, value: 90.0 },
            SummaryQuantile { quantile: 0.99, value: 99.0 },
        ];

        let sketch = summary_to_sketch(&quantiles, 100, 5000.0);
        assert!(sketch.count > 0.0);
        assert_eq!(sketch.sum, 5000.0);

        let p50 = sketch.quantile(0.50).unwrap();
        assert!(p50 > 40.0 && p50 < 60.0, "p50 = {}", p50);
    }

    #[test]
    fn test_summary_to_sketch_nan_inf() {
        let quantiles = vec![
            SummaryQuantile { quantile: 0.25, value: f64::NAN },
            SummaryQuantile { quantile: 0.5, value: 50.0 },
            SummaryQuantile { quantile: 0.75, value: f64::INFINITY },
        ];

        let sketch = summary_to_sketch(&quantiles, 100, 5000.0);
        // Should handle NaN/Inf gracefully
        assert!(sketch.count > 0.0);
    }

    #[test]
    fn test_summary_to_sketch_empty() {
        let sketch = summary_to_sketch(&[], 0, 0.0);
        assert_eq!(sketch.count, 0.0);
    }
}
