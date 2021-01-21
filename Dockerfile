FROM python:3.8-slim-buster

ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

COPY ./ /opt/serviceregistrator/
WORKDIR /opt/serviceregistrator/

RUN /opt/venv/bin/python -m pip install --upgrade pip
RUN pip install -r requirements/base.txt
RUN python setup.py test
RUN pip install .

ENTRYPOINT ["serviceregistrator"]
