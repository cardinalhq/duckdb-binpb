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

//! Common utilities shared across metrics, logs, and traces processing.

use flate2::read::GzDecoder;
use std::{error::Error, fs::File, io::Read};

use crate::opentelemetry::proto::common::v1::{any_value, AnyValue};

/// Convert AnyValue to a string representation
pub fn any_value_to_string(value: &Option<AnyValue>) -> String {
    match value {
        Some(av) => match &av.value {
            Some(any_value::Value::StringValue(s)) => s.clone(),
            Some(any_value::Value::BoolValue(b)) => b.to_string(),
            Some(any_value::Value::IntValue(i)) => i.to_string(),
            Some(any_value::Value::DoubleValue(d)) => d.to_string(),
            Some(any_value::Value::BytesValue(b)) => hex::encode(b),
            Some(any_value::Value::ArrayValue(_)) => "[array]".to_string(),
            Some(any_value::Value::KvlistValue(_)) => "[kvlist]".to_string(),
            None => String::new(),
        },
        None => String::new(),
    }
}

/// Read file contents, decompressing if gzipped
pub fn read_binpb_file(path: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();

    if path.ends_with(".gz") {
        let mut decoder = GzDecoder::new(file);
        decoder.read_to_end(&mut buffer)?;
    } else {
        file.read_to_end(&mut buffer)?;
    }

    Ok(buffer)
}
