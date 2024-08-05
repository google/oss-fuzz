# Usage
Under `OSS-Fuzz` root directory:
```bash
export PROJECT=libiec61850
docker run -ti --entrypoint="compile" --name "${PROJECT}-origin" "gcr.io/oss-fuzz/${PROJECT}"
docker commit "${PROJECT}-origin" "gcr.io/oss-fuzz/${PROJECT}-ofg-cached"
docker run -ti --entrypoint="recompile" "gcr.io/oss-fuzz/${PROJECT}-ofg-cached" 
```
