// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Shim: re-export parking_lot primitives under the fuchsia_sync name.
// The real fuchsia-sync crate wraps parking_lot on non-Fuchsia targets;
// this shim provides exactly the same interface for OSS-Fuzz (Linux x86_64).
pub use parking_lot::Mutex;
pub use parking_lot::MutexGuard;
pub use parking_lot::RwLock;
pub use parking_lot::RwLockReadGuard;
pub use parking_lot::RwLockWriteGuard;
