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
extern crate libc;
use self::libc::{c_char, c_int, c_void, size_t};
use std::io::{IoError};
use std::c_vec::CVec;
use std::c_str::CString;
use std::str::from_utf8;

use rocksdb_ffi;
use options::RocksDBOptions;

pub struct RocksDB {
    inner: rocksdb_ffi::RocksDBInstance,
}

impl RocksDB {
    pub fn open_default(path: &str) -> Result<RocksDB, String> {
        let mut opts = RocksDBOptions::new();
        opts.create_if_missing(true);
        RocksDB::open(opts, path)
    }

    pub fn open<'a>(opts: RocksDBOptions, path: &str) -> Result<RocksDB, String> {
        unsafe {
            let cpath = path.to_c_str();
            let cpath_ptr = cpath.as_ptr();

            //TODO test path here, as if rocksdb fails it will just crash the
            //     process currently

            let err = 0 as *mut i8;
            let db = rocksdb_ffi::rocksdb_open(opts.inner, cpath_ptr, err);
            let rocksdb_ffi::RocksDBInstance(db_ptr) = db;
            if err.is_not_null() {
                let cs = CString::new(err as *const i8, true);
                match cs.as_str() {
                    Some(error_string) =>
                        return Err(error_string.to_string()),
                    None =>
                        return Err(
                            "Could not initialize database.".to_string()),
                }
            }
            if db_ptr.is_null() {
                return Err("Could not initialize database.".to_string());
            }
            Ok(RocksDB{inner: db})
        }
    }

    pub fn destroy(opts: RocksDBOptions, path: &str) -> Result<(), String> {
        unsafe {
            let cpath = path.to_c_str();
            let cpath_ptr = cpath.as_ptr();

            //TODO test path here, as if rocksdb fails it will just crash the
            //     process currently

            let err = 0 as *mut i8;
            let result = rocksdb_ffi::rocksdb_destroy_db(
                opts.inner, cpath_ptr, err);
            if err.is_not_null() {
                let cs = CString::new(err as *const i8, true);
                match cs.as_str() {
                    Some(error_string) =>
                        return Err(error_string.to_string()),
                    None =>
                        return Err(
                            "Could not initialize database.".to_string()),
                }
            }
            Ok(())
        }
    }

    pub fn put(self, key: &[u8], value: &[u8]) -> Result<(), String> {
        unsafe {
            let writeopts = rocksdb_ffi::rocksdb_writeoptions_create();
            let err = 0 as *mut i8;
            rocksdb_ffi::rocksdb_put(self.inner, writeopts, key.as_ptr(),
                        key.len() as size_t, value.as_ptr(),
                        value.len() as size_t, err);
            if err.is_not_null() {
                let cs = CString::new(err as *const i8, true);
                match cs.as_str() {
                    Some(error_string) =>
                        return Err(error_string.to_string()),
                    None => {
                        let ie = IoError::last_error();
                        return Err(format!(
                                "ERROR: desc:{}, details:{}",
                                ie.desc,
                                ie.detail.unwrap_or_else(
                                    || {"none provided by OS".to_string()})))
                    }
                }
            }
            return Ok(())
        }
    }

    pub fn merge(self, key: &[u8], value: &[u8]) -> Result<(), String> {
        unsafe {
            let writeopts = rocksdb_ffi::rocksdb_writeoptions_create();
            let err = 0 as *mut i8;
            rocksdb_ffi::rocksdb_merge(self.inner, writeopts, key.as_ptr(),
                        key.len() as size_t, value.as_ptr(),
                        value.len() as size_t, err);
            if err.is_not_null() {
                let cs = CString::new(err as *const i8, true);
                match cs.as_str() {
                    Some(error_string) =>
                        return Err(error_string.to_string()),
                    None => {
                        let ie = IoError::last_error();
                        return Err(format!(
                                "ERROR: desc:{}, details:{}",
                                ie.desc,
                                ie.detail.unwrap_or_else(
                                    || {"none provided by OS".to_string()})))
                    }
                }
            }
            return Ok(())
        }
    }


    pub fn get<'a>(self, key: &[u8]) ->
        RocksDBResult<'a, RocksDBVector, String> {
        unsafe {
            let readopts = rocksdb_ffi::rocksdb_readoptions_create();
            let rocksdb_ffi::RocksDBReadOptions(read_opts_ptr) = readopts;
            if read_opts_ptr.is_null() {
                return RocksDBResult::Error("Unable to create rocksdb read \
                    options.  This is a fairly trivial call, and its failure \
                    may be indicative of a mis-compiled or mis-loaded rocksdb \
                    library.".to_string());
            }

            let val_len: size_t = 0;
            let val_len_ptr = &val_len as *const size_t;
            let err = 0 as *mut i8;
            let val = rocksdb_ffi::rocksdb_get(self.inner, readopts,
                key.as_ptr(), key.len() as size_t, val_len_ptr, err) as *mut u8;
            if err.is_not_null() {
                let cs = CString::new(err as *const i8, true);
                match cs.as_str() {
                    Some(error_string) =>
                        return RocksDBResult::Error(error_string.to_string()),
                    None =>
                        return RocksDBResult::Error("Unable to get value from \
                            rocksdb. (non-utf8 error received from underlying \
                            library)".to_string()),
                }
            }
            match val.is_null() {
                true =>    RocksDBResult::None,
                false => {
                    RocksDBResult::Some(RocksDBVector::from_c(val, val_len))
                }
            }
        }
    }

    pub fn delete(self, key: &[u8]) -> Result<(),String> {
        unsafe {
            let writeopts = rocksdb_ffi::rocksdb_writeoptions_create();
            let err = 0 as *mut i8;
            rocksdb_ffi::rocksdb_delete(self.inner, writeopts, key.as_ptr(),
                        key.len() as size_t, err);
            if err.is_not_null() {
                let cs = CString::new(err as *const i8, true);
                match cs.as_str() {
                    Some(error_string) =>
                        return Err(error_string.to_string()),
                    None => {
                        let ie = IoError::last_error();
                        return Err(format!(
                                "ERROR: desc:{}, details:{}",
                                ie.desc,
                                ie.detail.unwrap_or_else(
                                    || {"none provided by OS".to_string()})))
                    }
                }
            }
            return Ok(())
        }
    }

    pub fn close(self) {
        unsafe { rocksdb_ffi::rocksdb_close(self.inner); }
    }
}

pub struct RocksDBVector {
    inner: CVec<u8>,
}

impl RocksDBVector {
    pub fn from_c(val: *mut u8, val_len: size_t) -> RocksDBVector {
        unsafe {
            RocksDBVector {
                inner:
                    CVec::new_with_dtor(val, val_len as uint,
                        move|:|{ libc::free(val as *mut c_void); })
            }
        }
    }

    pub fn as_slice<'a>(&'a self) -> &'a [u8] {
        self.inner.as_slice()
    }

    pub fn to_utf8<'a>(&'a self) -> Option<&'a str> {
        from_utf8(self.inner.as_slice())
    }
}

// RocksDBResult exists because of the inherent difference between
// an operational failure and the absence of a possible result.
#[deriving(Clone, PartialEq, PartialOrd, Eq, Ord, Show)]
pub enum RocksDBResult<'a,T,E> {
    Some(T),
    None,
    Error(E),
}

impl <'a,T,E> RocksDBResult<'a,T,E> {
    #[unstable = "waiting for unboxed closures"]
    pub fn map<U>(self, f: |T| -> U) -> RocksDBResult<U,E> {
        match self {
            RocksDBResult::Some(x) => RocksDBResult::Some(f(x)),
            RocksDBResult::None => RocksDBResult::None,
            RocksDBResult::Error(e) => RocksDBResult::Error(e),
        }
    }

    pub fn unwrap(self) -> T {
        match self {
            RocksDBResult::Some(x) => x,
            RocksDBResult::None =>
                panic!("Attempted unwrap on RocksDBResult::None"),
            RocksDBResult::Error(_) =>
                panic!("Attempted unwrap on RocksDBResult::Error"),
        }
    }

    #[unstable = "waiting for unboxed closures"]
    pub fn on_error<U>(self, f: |E| -> U) -> RocksDBResult<T,U> {
        match self {
            RocksDBResult::Some(x) => RocksDBResult::Some(x),
            RocksDBResult::None => RocksDBResult::None,
            RocksDBResult::Error(e) => RocksDBResult::Error(f(e)),
        }
    }

    #[unstable = "waiting for unboxed closures"]
    pub fn on_absent(self, f: || -> ()) -> RocksDBResult<T,E> {
        match self {
            RocksDBResult::Some(x) => RocksDBResult::Some(x),
            RocksDBResult::None => {
                f();
                RocksDBResult::None
            },
            RocksDBResult::Error(e) => RocksDBResult::Error(e),
        }
    }

    pub fn is_some(self) -> bool {
        match self {
            RocksDBResult::Some(_) => true,
            RocksDBResult::None => false,
            RocksDBResult::Error(_) => false,
        }
    }
    pub fn is_none(self) -> bool {
        match self {
            RocksDBResult::Some(_) => false,
            RocksDBResult::None => true,
            RocksDBResult::Error(_) => false,
        }
    }
    pub fn is_error(self) -> bool {
        match self {
            RocksDBResult::Some(_) => false,
            RocksDBResult::None => false,
            RocksDBResult::Error(_) => true,
        }
    }
}

#[allow(dead_code)]
#[test]
fn external() {
    let path = "_rust_rocksdb_externaltest";
    let db = RocksDB::open_default(path).unwrap();
    let p = db.put(b"k1", b"v1111");
    assert!(p.is_ok());
    let r: RocksDBResult<RocksDBVector, String> = db.get(b"k1");
    assert!(r.unwrap().to_utf8().unwrap() == "v1111");
    assert!(db.delete(b"k1").is_ok());
    assert!(db.get(b"k1").is_none());
    db.close();
    let opts = RocksDBOptions::new();
    assert!(RocksDB::destroy(opts, path).is_ok());
}
