-- Copyright 2026 Google LLC

-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the
-- License.
-- You may obtain a copy of the License at
--
--      http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing,
-- software distributed under the License is distributed on an
-- "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
-- either express or implied.
-- See the License for the specific language governing permissions
-- and limitations under the License.

local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(4)

    local b = {}
    str:gsub(".", function(c) table.insert(b, c) end)
    local count = 0
    if b[1] == "o" then count = count + 1 end
    if b[2] == "o" then count = count + 1 end
    if b[3] == "p" then count = count + 1 end
    if b[4] == "s" then count = count + 1 end

    if count == 4 then assert(nil) end
end

local args = {
    only_ascii = 1,
    print_pcs = 1,
}

luzer.Fuzz(TestOneInput, nil, args)
