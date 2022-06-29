FROM rustlang/rust:nightly
WORKDIR /itoa
COPY . .
RUN cargo install cargo-fuzz
RUN cargo fuzz run decode -- -runs=0
