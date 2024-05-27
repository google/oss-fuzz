#!/bin/bash -ex

docker build -t oss-fuzz-blog .

rm -rf site
mkdir -p site

docker build -t oss-fuzz-blog .
docker run --rm -ti -v $(pwd)/site:/site oss-fuzz-blog sh -c 'cp -r /oss-fuzz-blog/page/public /site && chmod -R 777 /site'

gsutil -h "Cache-Control:no-cache,max-age=0" -m cp -r site/public/* gs://oss-fuzz-blog
