FROM alpine:3
COPY find-guardduty-user /bin/find-guardduty-user
ENTRYPOINT [ "find-guardduty-user" ]
