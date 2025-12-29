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

//! DuckDB extension for reading OpenTelemetry binary protobuf files.
//!
//! This extension provides table functions for reading OpenTelemetry
//! metrics, logs, and traces from binary protobuf (.binpb) files.

extern crate duckdb;
extern crate libduckdb_sys;

pub mod common;
pub mod fingerprint;
pub mod logs;
pub mod metrics;
pub mod normalize;
pub mod sketch;
pub mod tid;
pub mod traces;

// Include generated protobuf code
pub mod opentelemetry {
    pub mod proto {
        pub mod common {
            pub mod v1 {
                include!("opentelemetry.proto.common.v1.rs");
            }
        }
        pub mod resource {
            pub mod v1 {
                include!("opentelemetry.proto.resource.v1.rs");
            }
        }
        pub mod metrics {
            pub mod v1 {
                include!("opentelemetry.proto.metrics.v1.rs");
            }
        }
        pub mod logs {
            pub mod v1 {
                include!("opentelemetry.proto.logs.v1.rs");
            }
        }
        pub mod trace {
            pub mod v1 {
                include!("opentelemetry.proto.trace.v1.rs");
            }
        }
        pub mod collector {
            pub mod metrics {
                pub mod v1 {
                    include!("opentelemetry.proto.collector.metrics.v1.rs");
                }
            }
            pub mod logs {
                pub mod v1 {
                    include!("opentelemetry.proto.collector.logs.v1.rs");
                }
            }
            pub mod trace {
                pub mod v1 {
                    include!("opentelemetry.proto.collector.trace.v1.rs");
                }
            }
        }
    }
}

use duckdb::Connection;
use libduckdb_sys as ffi;
use std::error::Error;

// ============================================================================
// Extension entry point
// ============================================================================

const MINIMUM_DUCKDB_VERSION: &str = "v1.2.0";

unsafe fn extension_entrypoint_internal(
    info: ffi::duckdb_extension_info,
    access: *const ffi::duckdb_extension_access,
) -> Result<bool, Box<dyn Error>> {
    let have_api_struct = ffi::duckdb_rs_extension_api_init(info, access, MINIMUM_DUCKDB_VERSION)
        .map_err(|e| format!("Failed to init API: {:?}", e))?;

    if !have_api_struct {
        return Ok(false);
    }

    let db: ffi::duckdb_database = *(*access).get_database.unwrap()(info);
    let con = Connection::open_from_raw(db.cast())?;

    // Register table functions
    metrics::register(&con)?;
    logs::register(&con)?;
    traces::register(&con)?;

    Ok(true)
}

#[no_mangle]
pub unsafe extern "C" fn otel_binpb_init_c_api(
    info: ffi::duckdb_extension_info,
    access: *const ffi::duckdb_extension_access,
) -> bool {
    match extension_entrypoint_internal(info, access) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("OTel binpb extension init failed: {}", e);
            false
        }
    }
}
