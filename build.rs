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

use std::io::Result;

fn main() -> Result<()> {
    // Tell Cargo to rerun this build script if any proto files change
    println!("cargo:rerun-if-changed=proto/");

    let proto_files = [
        "proto/opentelemetry/proto/common/v1/common.proto",
        "proto/opentelemetry/proto/resource/v1/resource.proto",
        "proto/opentelemetry/proto/metrics/v1/metrics.proto",
        "proto/opentelemetry/proto/collector/metrics/v1/metrics_service.proto",
        "proto/opentelemetry/proto/logs/v1/logs.proto",
        "proto/opentelemetry/proto/collector/logs/v1/logs_service.proto",
        "proto/opentelemetry/proto/trace/v1/trace.proto",
        "proto/opentelemetry/proto/collector/trace/v1/trace_service.proto",
    ];

    prost_build::Config::new()
        .out_dir("src/")
        .compile_protos(&proto_files, &["proto/"])?;

    Ok(())
}
