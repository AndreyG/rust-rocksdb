rust-rocksdb
============
[![Build Status](https://travis-ci.org/spacejam/rust-rocksdb.svg?branch=master)](https://travis-ci.org/spacejam/rust-rocksdb)

This library has been tested against RocksDB 3.8.1 on linux and OSX.  The 0.0.4 crate should work with the 1.0.0-alpha.2 Rust release.  Currently, travis is only testing the nightly, but this may change when the beta drops.
###### Prerequisite: RocksDB
```bash
wget https://github.com/facebook/rocksdb/archive/rocksdb-3.8.tar.gz
tar xvf rocksdb-3.8.tar.gz && cd rocksdb-rocksdb-3.8 && make static_lib
sudo make install
```

### Running
###### Cargo.toml
```rust
[dependencies]
rocksdb = "~0.0.4"
```
###### Code
```rust
extern crate rocksdb;
use rocksdb::RocksDB;

fn main() {
    let db = RocksDB::open_default("/path/for/rocksdb/storage").unwrap();
    db.put(b"my key", b"my value");
    db.get(b"my key")
        .map( |value| { 
            println!("retrieved value {}", value.to_utf8().unwrap())
        })
        .on_absent( || { println!("value not found") })
        .on_error( |e| { println!("operational problem encountered: {}", e) });

    db.delete(b"my key");
    db.close();
}
```

###### Rustic Merge Operator
```rust
extern crate rocksdb;
use rocksdb::{RocksDBOptions, RocksDB, MergeOperands};

fn concat_merge(new_key: &[u8], existing_val: Option<&[u8]>,
    operands: &mut MergeOperands) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(operands.size_hint().0);
    existing_val.map(|v| { result.push_all(v) });
    for op in operands {
        result.push_all(op);
    }
    result
}

fn main() {
    let path = "/path/to/rocksdb";
    let opts = RocksDBOptions::new();
    opts.create_if_missing(true);
    opts.add_merge_operator("test operator", concat_merge);
    let db = RocksDB::open(opts, path).unwrap();
    let p = db.put(b"k1", b"a");
    db.merge(b"k1", b"b");
    db.merge(b"k1", b"c");
    db.merge(b"k1", b"d");
    db.merge(b"k1", b"efg");
    let r = db.get(b"k1");
    assert!(r.unwrap().to_utf8().unwrap() == "abcdefg");
    db.close();
}
```

###### Apply Some Tunings
Please read [the official tuning guide](https://github.com/facebook/rocksdb/wiki/RocksDB-Tuning-Guide), and most importantly, measure performance under realistic workloads with realistic hardware.
```rust
use rocksdb::{RocksDBOptions, RocksDB, new_bloom_filter};
use rocksdb::RocksDBCompactionStyle::RocksDBUniversalCompaction;

fn tuned_for_somebody_elses_disk() -> RocksDB {
    let path = "_rust_rocksdb_optimizetest";
    let opts = RocksDBOptions::new();
    opts.create_if_missing(true);
    opts.set_block_size(524288);
    opts.set_max_open_files(10000);
    opts.set_use_fsync(false);
    opts.set_bytes_per_sync(8388608);
    opts.set_disable_data_sync(false);
    opts.set_block_cache_size_mb(1024);
    opts.set_table_cache_num_shard_bits(6);
    opts.set_max_write_buffer_number(32);
    opts.set_write_buffer_size(536870912);
    opts.set_target_file_size_base(1073741824);
    opts.set_min_write_buffer_number_to_merge(4);
    opts.set_level_zero_stop_writes_trigger(2000);
    opts.set_level_zero_slowdown_writes_trigger(0);
    opts.set_compaction_style(RocksDBUniversalCompaction);
    opts.set_max_background_compactions(4);
    opts.set_max_background_flushes(4);
    opts.set_filter_deletes(false);
    opts.set_disable_auto_compactions(true);

    let filter = new_bloom_filter(10);
    opts.set_filter(filter);

    RocksDB::open(opts, path).unwrap()
}
```

### status
  - [x] basic open/put/get/delete/close
  - [x] linux support
  - [x] rocksdb compiled via cargo
  - [x] OSX support
  - [x] rustic merge operator
  - [x] compaction filter, style
  - [x] LRU cache
  - [x] destroy/repair
  - [ ] create/release snapshot
  - [ ] iterator
  - [ ] column family operations
  - [ ] write batch
  - [ ] comparator
  - [ ] slicetransform
  - [ ] windows support

Feedback and pull requests welcome!  If a particular feature of RocksDB is important to you, please let me know by opening an issue, and I'll prioritize it.
