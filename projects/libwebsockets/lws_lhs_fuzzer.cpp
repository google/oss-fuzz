/* Copyright 2024 Google LLC
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
##############################################################################*/

#include <stdlib.h>
#include "libwebsockets.h"

static unsigned int m, step;

static int
dump_atr(lws_dll2_t *d, void *user)
{
	lws_container_of(d, lhp_atr_t, list);
	//lhp_atr_t *atr = lws_container_of(d, lhp_atr_t, list);
	//const char *p = (const char *)&atr[1];

	//printf("{ \"%.*s\", \"%.*s\" }, ",
	//	    (int)atr->name_len, p, (int)atr->value_len, p + atr->name_len + 1);

	return 0;
}

static lws_stateful_ret_t
test_cb(lhp_ctx_t *ctx, char reason)
{
	lhp_pstack_t *ps = lws_container_of(ctx->stack.tail, lhp_pstack_t, list);
	if (reason == LHPCB_ELEMENT_START || reason == LHPCB_ELEMENT_END) {
		lws_dll2_foreach_safe(&ps->atr, NULL, dump_atr);
		lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_DISPLAY);
		lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_COLOR);
		lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_FONT_SIZE);
		lws_css_cascade_get_prop_atr(ctx, LCSP_PROP_FONT_FAMILY);
	}
	return (lws_stateful_ret_t)0;
}

static const lws_surface_info_t ic = {
	.wh_px = { { 600,0 },       { 448,0 } },
	.wh_mm = { { 114,5000000 }, {  82,5000000 } },
};

static lws_displaylist_t displaylist;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, uint32_t size) {
	struct lws_context_creation_info info = {0};
	struct lws_context *cx = NULL;
	lhp_ctx_t ctx;
	lws_dl_rend_t drt;
	size_t ssize;
	const uint8_t *sdata;

	if (!size)
	  return (0);
	memset(&ctx, 0, sizeof(ctx));
	drt.dl = &displaylist;
	drt.w = ic.wh_px[0].whole;
	drt.h = ic.wh_px[1].whole;
	if (lws_lhp_construct(&ctx, test_cb, &drt, &ic))
		return (-1);

	lws_context_info_defaults(&info, NULL);
	if (!(cx = lws_create_context(&info)))
	  return (0);
	ctx.user1 = (uint8_t *)cx;

	ctx.flags = LHP_FLAG_DOCUMENT_END;
	if (!(ctx.base_url = strdup("")))
		return (-1);
	ssize = (size_t)size;
	sdata = data;
	lws_lhp_parse(&ctx, &sdata, &ssize);
	lws_lhp_destruct(&ctx);
	lws_context_destroy(cx);
	return (0);
}
