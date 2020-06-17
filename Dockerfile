FROM alpine:3
COPY bin/find-guardduty-user /bin/find-guardduty-user
ENTRYPOINT [ "find-guardduty-user" ]
