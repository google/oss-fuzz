/*
# SPDX-FileCopyrightText: 2025 Google LLC
# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <karchive.h>

inline void traverseArchive(const KArchiveDirectory *dir, const QString &path = QString())
{
    for (const auto &entryName : dir->entries()) {
        auto entry = dir->entry(entryName);

        if (entry->isFile()) {
            auto file = static_cast<const KArchiveFile *>(entry);
            auto data = file->data();
        } else if (entry->isDirectory()) {
            auto subDir = static_cast<const KArchiveDirectory *>(entry);
            traverseArchive(subDir, path + QString::fromUtf8("/") + entryName);
        }
    }
}
