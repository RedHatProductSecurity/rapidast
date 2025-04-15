#!/usr/bin/env python3
import datetime
import logging
import os
import random
import string
import tarfile
import uuid
from io import BytesIO

from google.cloud import storage


class GoogleCloudStorage:
    """
    Sends the results to a Google Cloud Storage bucket
    """

    def __init__(self, bucket_name, app_name, directory=None, keyfile=None):
        if keyfile:
            client = storage.Client.from_service_account_json(keyfile)
        else:
            client = storage.Client()
        try:
            self.bucket = client.get_bucket(bucket_name)
        except Exception as e:
            logging.error(f"Failed to get the bucket: {e}")
            raise

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

    def export_scan(self, result_dir_name):
        """
        Send the scan results to GCS.
        The results are sent as a tar file containing the results directory and its contents.
        The results have the same structure as they are stored locally.

        Params:
        result_dir_name: path to the root directory that contains scan results

        """
        if not result_dir_name:
            # missing data means nothing to do
            logging.error("GoogleCloudStorage: result_dir_name is not specified")
            return 1

        logging.info(f"GoogleCloudStorage: sending the contents of the directory: {result_dir_name}")

        # create a tar containing the directory and its contents
        tar_stream = BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
            tar.add(name=result_dir_name, arcname=f"{os.path.basename(result_dir_name)}")
        tar_stream.seek(0)

        # generate the blob filename
        unique_id = "{}-RapiDAST-{}-{}.tgz".format(  # pylint: disable=C0209
            datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
            self.app_name,
            "".join(random.choices(string.ascii_letters + string.ascii_uppercase + string.digits, k=6)),
        )
        blob_name = self.directory + "/" + unique_id

        # push to GCS
        blob = self.bucket.blob(blob_name)
        with blob.open(mode="wb") as dest:
            dest.write(tar_stream.getbuffer())

        return 0
