# 继承 OSS-Fuzz 官方提供的基础镜像
FROM gcr.io/oss-fuzz-base/base-builder

# 将所有项目文件复制到容器内 /src，helper.py 会在此处寻找 build.sh
COPY . $SRC

# 切到 /src 下执行 build.sh
WORKDIR $SRC

