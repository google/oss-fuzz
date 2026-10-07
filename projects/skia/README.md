When bench testing image_filter_deserialize, it may be useful to have
malloc_limit_mb = 500, and timeout = 10 to find actionable OOM culprits sooner.

When reproducing, add -malloc_limit_mb=100 -rss_limit_mb=0 after the
repro_test to locate where big memory allocations are happening.

    python infra/helper.py reproduce skia image_decode ~/Downloads/foo -malloc_limit_mb=100 -rss_limit_mb=0
