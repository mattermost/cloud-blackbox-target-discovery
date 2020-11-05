# Build the cloud blackbox target discovery
ARG DOCKER_BUILD_IMAGE=golang:1.14.10
ARG DOCKER_BASE_IMAGE=alpine:3.12

FROM ${DOCKER_BUILD_IMAGE} AS build
WORKDIR /cloud-blackbox-target-discovery/
COPY . /cloud-blackbox-target-discovery/
RUN apt-get update -yq && apt-get install -yq unzip
RUN make build


# Final Image
FROM ${DOCKER_BASE_IMAGE}
LABEL name="Mattermost Cloud Blackbox Target Discovery" \
  maintainer="cloud-team@mattermost.com" \
  vendor="Mattermost" \
  distribution-scope="public" \
  architecture="x86_64" \
  url="https://mattermost.com" \
  io.k8s.description="Mattermost Cloud Blackbox Target Discovery is responsible for registering new Blackbox probe targets" \
  io.k8s.display-name="Mattermost Cloud Blackbox Target Discovery"

ENV CLOUD=/cloud-blackbox-target-discovery/main \
    USER_UID=10001 \
    USER_NAME=cloud

RUN  apk update && apk add libc6-compat && apk add ca-certificates
COPY --from=build /cloud-blackbox-target-discovery/build/_output/bin/main /cloud-blackbox-target-discovery/main
COPY --from=build /cloud-blackbox-target-discovery/build/bin /usr/local/bin

RUN  /usr/local/bin/user_setup
WORKDIR /cloud-blackbox-target-discovery/

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER ${USER_UID}
