# Disposable target for a Caldera agent. Built while online (curl needed), then run ONLY on an
# --internal Docker network. Contains nothing of value. Delete it after the exercise.
FROM alpine:3.20
RUN apk add --no-cache curl procps
# Non-root user: the benign discovery abilities do not need root.
RUN adduser -D -u 10001 labuser
USER labuser
WORKDIR /home/labuser
CMD ["sleep", "infinity"]
