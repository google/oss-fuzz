---
layout: default
title: Corpora
parent: Advanced topics
nav_order: 3
permalink: /advanced-topics/corpora/
---

# Accessing Corpora
{: .no_toc}

If you want to access the corpora that we are using for your fuzz targets
(synthesized by the fuzzing engines), follow these steps.

- TOC
{:toc}
---

## Obtain access

To get access to a project's corpora, you must be listed as the
primary contact or as an auto cc in the project's `project.yaml` file, as described
in the [New Project Guide]({{ site.baseurl }}/getting-started/new-project-guide/#projectyaml).
If you don't do this, most of the links below won't work.

## Install Google Cloud SDK

The corpora for fuzz targets are stored on [Google Cloud
Storage](https://cloud.google.com/storage/). To access them, you need to
[install the gsutil
tool](https://cloud.google.com/storage/docs/gsutil_install), which is part of
the Google Cloud SDK. Follow the instructions on the installation page to
login with the Google account listed in your project's `project.yaml` file.

## Viewing the corpus for a fuzz target

The fuzzer statistics page for your project on
[ClusterFuzz]({{ site.baseurl }}/further-reading/clusterfuzz)
contains a link to the Google Cloud console for your corpus under the
**corpus_size** column. Click the link to browse and download individual test inputs in the
corpus.

![viewing_corpus](https://raw.githubusercontent.com/google/oss-fuzz/master/docs/images/viewing_corpus.png)

## Downloading the corpus 

If you want to download the entire corpus, click the link in the **corpus_size** column, then
copy the **Buckets** path at the top of the page:

![corpus_path](https://raw.githubusercontent.com/google/oss-fuzz/master/docs/images/corpus_path.png)

Copy the corpus to a directory on your
machine by running the following command:

```bash
$ gsutil -m cp -r gs://<bucket_path> <local_directory>
```
Using the expat example above, this would be:

```bash
$ gsutil -m cp -r \
    gs://expat-corpus.clusterfuzz-external.appspot.com/libFuzzer/expat_parse_fuzzer \
    <local_directory>
```

## Corpus backups

We keep daily zipped backups of your corpora. These can be accessed from the
**corpus_backup** column of the fuzzer statistics page. Downloading these can
be significantly faster than running `gsutil -m cp -r` on the corpus bucket.
