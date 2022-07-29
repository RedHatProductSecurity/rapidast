FROM quay.io/redhatproductsecurity/rapidast-base-zap:2.11.1a
COPY config/requirements.txt requirements.txt
USER root
RUN pip install -r requirements.txt

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
