FROM debian:stable-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential pkg-config libcurl4-openssl-dev
WORKDIR /src
COPY cf_ip_test_tls.c .
RUN cc -O2 -Wall -o cfip cf_ip_test_tls.c $(pkg-config --cflags --libs libcurl) -lpthread

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends libcurl4 ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/cfip .
COPY web ./web
ENV CFIP_BIND=0.0.0.0 CFIP_NO_BROWSER=1
VOLUME /app/data
EXPOSE 18443
CMD ["./cfip", "18443"]
