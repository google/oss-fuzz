# Accessing Corpora

If you would like to access the corpora that we are using for your fuzz targets (synthesized by the fuzzing engine), please follow these steps.

## Install Google Cloud SDK

[Install](https://cloud.google.com/storage/docs/gsutil_install) the gsutil tool, which is part of the Google Cloud SDK.
Follow the instructions on the installation page to login with a Google account thats listed in your project's `project.yaml`.

## Viewing the corpus for a fuzz target

The fuzzer statistics page for your project on [ClusterFuzz](clusterfuzz.md) will contain a link to the Google Cloud console for your corpus under the "corpus_size" column. 

![viewing_corpus]
(https://raw.githubusercontent.com/google/oss-fuzz/master/docs/images/viewing_corpus.png)

## Downloading the corpus 

TODO.

```bash
gsutil -m rsync gs://<corpus_path> <local_directory>
```
