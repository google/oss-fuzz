"use strict";
/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerInstrumentationPlugin = exports.instrumentationPlugins = exports.InstrumentationPlugins = void 0;
/**
 * Instrumentation plugins are can be used to add additional instrumentation by
 * bug detectors.
 */
class InstrumentationPlugins {
    _plugins = [];
    registerPlugin(plugin) {
        this._plugins.push(plugin);
    }
    get plugins() {
        return this._plugins;
    }
}
exports.InstrumentationPlugins = InstrumentationPlugins;
exports.instrumentationPlugins = new InstrumentationPlugins();
function registerInstrumentationPlugin(plugin) {
    exports.instrumentationPlugins.registerPlugin(plugin);
}
exports.registerInstrumentationPlugin = registerInstrumentationPlugin;
//# sourceMappingURL=plugin.js.map