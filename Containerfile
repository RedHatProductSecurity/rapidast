FROM owasp/zap2docker-stable:latest
USER root
RUN pip install jinja2

RUN chgrp -R 0 /zap && \
    chmod -R g=u /zap

RUN chgrp -R 0 /home/zap && \
    chmod -R g=u /home/zap 
USER zap
COPY scripts /zap/scripts
COPY policies /zap/policies
COPY entrypoint.sh .

ENTRYPOINT ["entrypoint.sh"]
CMD ["tmp"]
