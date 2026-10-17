/* Copyright 2023 Google LLC
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

#include "hdf5.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_FILE_SIZE (64 * 1024)

/* Limit iteration to avoid slow inputs */
#define MAX_OBJS    16
#define MAX_ATTRS   8
#define MAX_DEPTH   8

#define READ_BUF_SIZE 4096

static char fuzz_filename[256];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;

    H5Eset_auto2(H5E_DEFAULT, NULL, NULL);

    snprintf(fuzz_filename, sizeof(fuzz_filename),
             "/tmp/h5fuzz.%d", (int)getpid());
    return 0;
}

static void
fuzz_attrs(hid_t obj_id)
{
    int n_attrs, i;

    n_attrs = H5Aget_num_attrs(obj_id);
    if (n_attrs > MAX_ATTRS)
        n_attrs = MAX_ATTRS;

    for (i = 0; i < n_attrs; i++) {
        hid_t attr_id = H5Aopen_by_idx(obj_id, ".", H5_INDEX_NAME,
                                        H5_ITER_NATIVE, (hsize_t)i,
                                        H5P_DEFAULT, H5P_DEFAULT);
        if (attr_id == H5I_INVALID_HID)
            continue;

        hid_t atype = H5Aget_type(attr_id);
        if (atype != H5I_INVALID_HID) {
            H5Tget_class(atype);
            H5Tget_size(atype);
            H5Tclose(atype);
        }

        hid_t aspace = H5Aget_space(attr_id);
        if (aspace != H5I_INVALID_HID) {
            H5Sget_simple_extent_ndims(aspace);
            H5Sclose(aspace);
        }

        H5Aclose(attr_id);
    }
}

static void
fuzz_dataset(hid_t loc_id, const char *name)
{
    hid_t   dset_id;
    hid_t   space_id, type_id, dcpl_id;
    char    read_buf[READ_BUF_SIZE];

    dset_id = H5Dopen2(loc_id, name, H5P_DEFAULT);
    if (dset_id == H5I_INVALID_HID)
        return;

    type_id = H5Dget_type(dset_id);
    if (type_id != H5I_INVALID_HID) {
        H5Tget_class(type_id);
        H5Tget_size(type_id);


        if (H5Tget_size(type_id) > 0 && H5Tget_size(type_id) <= READ_BUF_SIZE) {
            space_id = H5Dget_space(dset_id);
            if (space_id != H5I_INVALID_HID) {
                hssize_t npoints = H5Sget_simple_extent_npoints(space_id);
                if (npoints > 0 &&
                    (hsize_t)npoints * H5Tget_size(type_id) <= READ_BUF_SIZE) {
                    H5Dread(dset_id, type_id, H5S_ALL, H5S_ALL,
                            H5P_DEFAULT, read_buf);
                }
                H5Sclose(space_id);
            }
        }
        H5Tclose(type_id);
    }


    dcpl_id = H5Dget_create_plist(dset_id);
    if (dcpl_id != H5I_INVALID_HID)
        H5Pclose(dcpl_id);


    fuzz_attrs(dset_id);

    H5Dclose(dset_id);
}

static void
fuzz_group(hid_t group_id, int depth)
{
    hsize_t  n_objs = 0;
    hsize_t  i;
    char     obj_name[256];
    H5G_info_t ginfo;

    if (depth >= MAX_DEPTH)
        return;

    H5Gget_info(group_id, &ginfo);

    fuzz_attrs(group_id);

    if (H5Gget_num_objs(group_id, &n_objs) < 0)
        return;

    if (n_objs > MAX_OBJS)
        n_objs = MAX_OBJS;

    for (i = 0; i < n_objs; i++) {
        ssize_t name_len;
        int     obj_type;

        name_len = H5Gget_objname_by_idx(group_id, i,
                                          obj_name, sizeof(obj_name));
        if (name_len <= 0)
            continue;

        obj_type = H5Gget_objtype_by_idx(group_id, i);
        switch (obj_type) {
        case H5G_DATASET:
            fuzz_dataset(group_id, obj_name);
            break;
        case H5G_GROUP: {
            hid_t child = H5Gopen2(group_id, obj_name, H5P_DEFAULT);
            if (child != H5I_INVALID_HID) {
                fuzz_group(child, depth + 1);
                H5Gclose(child);
            }
            break;
        }
        case H5G_TYPE: {
            hid_t tid = H5Topen2(group_id, obj_name, H5P_DEFAULT);
            if (tid != H5I_INVALID_HID) {
                H5Tget_class(tid);
                H5Tget_size(tid);
                H5Tclose(tid);
            }
            break;
        }
        default:
            break;
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FILE  *fp;
    hid_t  file_id, root_id;

    if (size < 8 || size > MAX_FILE_SIZE)
        return 0;

    fp = fopen(fuzz_filename, "wb");
    if (!fp)
        return 0;
    fwrite(data, 1, size, fp);
    fclose(fp);

    file_id = H5Fopen(fuzz_filename, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id != H5I_INVALID_HID) {
        root_id = H5Gopen2(file_id, "/", H5P_DEFAULT);
        if (root_id != H5I_INVALID_HID) {
            fuzz_group(root_id, 0);
            H5Gclose(root_id);
        }
        H5Fclose(file_id);
    }

    unlink(fuzz_filename);
    return 0;
}
