#!/usr/bin/env python3
import datetime
import json
import logging
import os
import random
import string
import tarfile
import uuid
from io import BytesIO
from io import StringIO

from google.cloud import storage


class GoogleCloudStorage:
    """
    Sends the results to a Google Cloud Storage bucket, for future use in DefectDojo
    """

    def __init__(self, bucket_name, app_name, directory=None, keyfile=None):
        if keyfile:
            client = storage.Client.from_service_account_json(keyfile)
        else:
            client = storage.Client()
        self.bucket = client.get_bucket(bucket_name)
        self.directory = directory or f"RapiDAST-{app_name}"
        self.app_name = app_name

    def create_metadata(self, data):
        """
        Given a dictionary of key/values corresponding to Defectdojo's `import-scan` parameters,
        return a Metadata dictionary
        """
        metadata = {
            "scan_type": data["scan_type"],
            "uuid": str(uuid.uuid1()),
            "import_data": data,
        }

        return metadata

    def export_scan(self, data, filename):
        """
        Send the scan to GCS

        Params:
        data: a dictionary of key/values corresponding to Defectdojo's `import-scan` parameters
        filename: path to the file containing scan

        """
        if not data or not filename:
            # missing data means nothing to do
            logging.debug("Insufficient data for Defect Dojo")
            return 1

        metadata = self.create_metadata(data)

        logging.info(
            f"GoogleCloudStorage: sending {filename}. UUID: {metadata['uuid']}"
        )

        # export data as a metadata.json file
        json_stream = StringIO()
        json.dump(metadata, json_stream)
        json_stream = BytesIO(json_stream.getvalue().encode("utf-8"))
        json_stream.seek(0)

        # create a tar containing: "scans/<filename>" and metadata.json
        tar_stream = BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
            # add the metadata
            info = tarfile.TarInfo(name="metadata.json")
            info.size = len(json_stream.getvalue())
            tar.addfile(tarinfo=info, fileobj=json_stream)

            # add the scan
            tar.add(name=filename, arcname=f"scans/{os.path.basename(filename)}")
        tar_stream.seek(0)

        # generate the blob filename
        unique_id = "{}-RapiDAST-{}-{}.tgz".format(  # pylint: disable=C0209
            datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
            self.app_name,
            "".join(
                random.choices(
                    string.ascii_letters + string.ascii_uppercase + string.digits, k=6
                )
            ),
        )
        blob_name = self.directory + "/" + unique_id

        # push to GCS
        blob = self.bucket.blob(blob_name)
        with blob.open(mode="wb") as dest:
            dest.write(tar_stream.getbuffer())
