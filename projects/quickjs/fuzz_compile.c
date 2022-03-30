/* Copyright 2020 Google Inc.
 
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

#include "quickjs-libc.h"
#include "cutils.h"

#include <stdint.h>
#include <stdio.h>

static int initialized = 0;
JSRuntime *rt;
JSContext *ctx;
static int nbinterrupts = 0;

// handle timeouts from infinite loops
static int interrupt_handler(JSRuntime *rt, void *opaque)
{
    nbinterrupts++;
    return (nbinterrupts > 100);
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (initialized == 0) {
        rt = JS_NewRuntime();
        // 64 Mo
        JS_SetMemoryLimit(rt, 0x4000000);
        //TODO JS_SetMaxStackSize ?
        ctx = JS_NewContextRaw(rt);
        JS_SetModuleLoaderFunc(rt, NULL, js_module_loader, NULL);
        JS_AddIntrinsicBaseObjects(ctx);
        JS_AddIntrinsicDate(ctx);
        JS_AddIntrinsicEval(ctx);
        JS_AddIntrinsicStringNormalize(ctx);
        JS_AddIntrinsicRegExp(ctx);
        JS_AddIntrinsicJSON(ctx);
        JS_AddIntrinsicProxy(ctx);
        JS_AddIntrinsicMapSet(ctx);
        JS_AddIntrinsicTypedArrays(ctx);
        JS_AddIntrinsicPromise(ctx);
        JS_AddIntrinsicBigInt(ctx);
        JS_SetInterruptHandler(JS_GetRuntime(ctx), interrupt_handler, NULL);
        js_std_add_helpers(ctx, 0, NULL);
        initialized = 1;
    }

    if (Size > 0) {
        if (Data[Size-1] != 0) {
            return 0;
        }
        JSValue obj;
        obj = JS_Eval(ctx, (const char *)Data, Size-1, "<none>", JS_EVAL_FLAG_COMPILE_ONLY | JS_EVAL_TYPE_GLOBAL | JS_EVAL_TYPE_MODULE);
        //TODO target with JS_ParseJSON
        if (JS_IsException(obj)) {
            return 0;
        }
        size_t bytecode_size;
        uint8_t* bytecode = JS_WriteObject(ctx, &bytecode_size, obj, JS_WRITE_OBJ_BYTECODE);
        JS_FreeValue(ctx, obj);
        if ( !bytecode ) {
            return 0;
        }
        obj = JS_ReadObject(ctx, bytecode, bytecode_size, JS_READ_OBJ_BYTECODE);
        if (JS_IsException(obj)) {
            js_free(ctx, bytecode);
            return 0;
        }
        nbinterrupts = 0;
        /* this is based on
         * js_std_eval_binary(ctx, bytecode, bytecode_size, 0);
         * modified so as not to exit on JS exception
         */
        JSValue val;
        if (JS_VALUE_GET_TAG(obj) == JS_TAG_MODULE) {
            if (JS_ResolveModule(ctx, obj) < 0) {
                JS_FreeValue(ctx, obj);
                js_free(ctx, bytecode);
                return 0;
            }
            js_module_set_import_meta(ctx, obj, FALSE, TRUE);
        }
        val = JS_EvalFunction(ctx, obj);
        if (JS_IsException(val)) {
            js_std_dump_error(ctx);
        } else {
            js_std_loop(ctx);
        }
        JS_FreeValue(ctx, val);
        js_free(ctx, bytecode);
    }

    return 0;
}
