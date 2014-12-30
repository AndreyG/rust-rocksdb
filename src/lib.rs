/*
   Copyright 2014 Tyler Neely

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
#![crate_id = "rocksdb"]
#![crate_type = "lib"]
#![allow(dead_code)]

pub use ffi as rocksdb_ffi;
pub use ffi::{
    new_bloom_filter,
    new_cache,
    RocksDBUniversalCompactionStyle,
    RocksDBCompactionStyle,
    RocksDBCompressionType,
};
pub use rocksdb::{
    RocksDB,
    RocksDBResult,
    RocksDBVector,
};
pub use options::{
    RocksDBOptions,
};
pub use mergeoperator::{
    MergeOperands,
};

pub mod rocksdb;
pub mod ffi;
pub mod options;
pub mod mergeoperator;
