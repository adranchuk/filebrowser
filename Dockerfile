FROM node:16-alpine AS BUILDER 
RUN apk update
RUN apk add --update go make bash ca-certificates mailcap curl 
# ENV NODE_OPTION=--openssl-legacy-provider
COPY . /app/
WORKDIR /app

RUN make build


FROM alpine:latest
RUN apk --update add ca-certificates \
                     mailcap \
                     curl

HEALTHCHECK --start-period=2s --interval=5s --timeout=3s \
  CMD curl -f http://localhost/health || exit 1

VOLUME /srv
EXPOSE 80

COPY  docker_config.json /.filebrowser.json
COPY  --from=builder /app/filebrowser /filebrowser

ENTRYPOINT [ "/filebrowser" ]
