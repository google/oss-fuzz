FROM rustlang/rust:nightly
WORKDIR /ryu
COPY . .
RUN cargo install cargo-fuzz
RUN cargo fuzz run decode -- -runs=0
