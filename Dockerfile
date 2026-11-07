FROM rust:1 AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p medcrypto --bin medcrypto

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/medcrypto /usr/local/bin/medcrypto
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/medcrypto"]
