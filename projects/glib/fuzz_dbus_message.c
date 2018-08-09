#include "gio/gio.h"
#include <stdint.h>

static GDBusCapabilityFlags flags = G_DBUS_CAPABILITY_FLAGS_UNIX_FD_PASSING;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  gssize bytes = g_dbus_message_bytes_needed((guchar*)data, size, NULL);
  if (bytes <= 0 || bytes > (100 << 20))
    return 0;

  g_autoptr(GDBusMessage) msg =
      g_dbus_message_new_from_blob((guchar*)data, size, flags, NULL);
  if (!msg)
    return 0;

  gsize msg_size;
  g_autofree guchar* blob = g_dbus_message_to_blob(msg, &msg_size, flags, NULL);
  return 0;
}
