/*
 * Copyright 2016 Google Inc.
 * author: Edward Hervey <bilboed@bilboed.com>
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
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <locale.h>

#include <stdlib.h>
#include <glib.h>
#include <gst/gst.h>
#include <gst/pbutils/pbutils.h>

GST_PLUGIN_STATIC_DECLARE(coreelements);
GST_PLUGIN_STATIC_DECLARE(playback);
GST_PLUGIN_STATIC_DECLARE(typefindfunctions);
GST_PLUGIN_STATIC_DECLARE(app);
GST_PLUGIN_STATIC_DECLARE(ogg);
GST_PLUGIN_STATIC_DECLARE(theora);
GST_PLUGIN_STATIC_DECLARE(vorbis);


static void
print_info (GstDiscovererInfo * info, GError * err)
{
  GstDiscovererResult result;

  if (!info) {
    g_print ("Could not discover URI\n");
    g_print (" %s\n", err->message);
    return;
  }

  result = gst_discoverer_info_get_result (info);
  g_print ("Done discovering %s\n", gst_discoverer_info_get_uri (info));
  switch (result) {
    case GST_DISCOVERER_OK:
    {
      g_print ("All good\n");
      break;
    }
    case GST_DISCOVERER_URI_INVALID:
    {
      g_print ("URI is not valid\n");
      break;
    }
    case GST_DISCOVERER_ERROR:
    {
      g_print ("An error was encountered while discovering the file\n");
      g_print (" %s\n", err->message);
      break;
    }
    case GST_DISCOVERER_TIMEOUT:
    {
      g_print ("Analyzing URI timed out\n");
      break;
    }
    case GST_DISCOVERER_BUSY:
    {
      g_print ("Discoverer was busy\n");
      break;
    }
    case GST_DISCOVERER_MISSING_PLUGINS:
    {
      g_print ("Missing plugins\n");
      break;
    }
  }

  g_print ("\n");
}

const guint8 *fuzztesting_data;
size_t fuzztesting_size;

static void
appsrc_configuration (GstDiscoverer *dc, GstElement *source, gpointer data)
{
  GstBuffer *buf;
  GstFlowReturn ret;
  
  /* Create buffer from fuzztesting_data */
  buf = gst_buffer_new_wrapped ((gpointer) fuzztesting_data, fuzztesting_size);
  g_object_set (G_OBJECT (source), "size", fuzztesting_size, NULL);
  g_signal_emit_by_name (G_OBJECT(source), "push-buffer", buf, &ret);
}

int LLVMFuzzerTestOneInput(const guint8 *data, size_t size)
{
  GError *err = NULL;
  GstDiscoverer *dc;
  gint timeout = 10;
  GstDiscovererInfo *info;

  gst_init (NULL, NULL);
  
  GST_PLUGIN_STATIC_REGISTER(coreelements);
  GST_PLUGIN_STATIC_REGISTER(playback);
  GST_PLUGIN_STATIC_REGISTER(typefindfunctions);
  GST_PLUGIN_STATIC_REGISTER(app);
  GST_PLUGIN_STATIC_REGISTER(ogg);
  GST_PLUGIN_STATIC_REGISTER(theora);
  GST_PLUGIN_STATIC_REGISTER(vorbis);
  
  dc = gst_discoverer_new (timeout * GST_SECOND, &err);
  if (G_UNLIKELY (dc == NULL)) {
    g_print ("Error initializing: %s\n", err->message);
    g_clear_error (&err);
    exit (1);
  }

  fuzztesting_data = data;
  fuzztesting_size = size;
  
  /* Connect to source-setup signal to give the data */
  g_signal_connect (dc, "source-setup", (GCallback) appsrc_configuration, NULL);
  
  info = gst_discoverer_discover_uri (dc, "appsrc://", &err);
  print_info (info, err);
  g_clear_error (&err);
  if (info)
    gst_discoverer_info_unref (info);
  
  g_object_unref (dc);
  
  return 0;
 }
 
