import logging
import os
import shutil
import tempfile
import time
from functools import partial
from typing import Dict
from typing import Optional

import certifi
import pytest
from kubernetes import client
from kubernetes import config
from kubernetes import utils
from kubernetes import watch
from kubernetes.client.rest import ApiException

NAMESPACE = os.getenv("RAPIDAST_NAMESPACE", "")  # e.g. rapidast--pipeline
SERVICEACCOUNT = os.getenv("RAPIDAST_SERVICEACCOUNT", "pipeline")  # name of ServiceAccount used in rapidast pod
RAPIDAST_IMAGE = os.getenv("RAPIDAST_IMAGE", "quay.io/redhatproductsecurity/rapidast:development")
RAPIDAST_LLM_IMAGE = os.getenv("RAPIDAST_IMAGE", "quay.io/redhatproductsecurity/rapidast-llm:development")
# delete resources created by tests
RAPIDAST_CLEANUP = os.getenv("RAPIDAST_CLEANUP", "True").lower() in ("true", "1", "t", "y", "yes")

MANIFESTS = "e2e-tests/manifests"


# monkeypatch certifi so that internal CAs are trusted
def where():
    return os.getenv("REQUESTS_CA_BUNDLE", "/etc/pki/tls/certs/ca-bundle.crt")


certifi.where = where


def wait_until_ready(**kwargs):
    corev1 = client.CoreV1Api()
    timeout = kwargs.pop("timeout", 120)

    start_time = time.time()

    while time.time() - start_time < timeout:
        time.sleep(2)
        try:
            pods = corev1.list_namespaced_pod(namespace=NAMESPACE, **kwargs)
        except client.ApiException as e:
            logging.error(f"Error checking pod status: {e}")
            return False

        if len(pods.items) != 1:
            raise RuntimeError(f"Unexpected number of pods {len(pods.items)} matching: {kwargs}")
        pod = pods.items[0]

        # Check if pod is ready by looking at conditions
        if pod.status.conditions:
            for condition in pod.status.conditions:
                if condition.type == "Ready":
                    logging.info(f"{pod.metadata.name} Ready={condition.status}")
                    if condition.status == "True":
                        return True
    return False


def is_pod_with_field_selector_successfully_completed(field_selector: str, timeout: int = 120) -> bool:
    """
    Checks if a given pod has successfully completed (Succeeded phase)
    """
    corev1 = client.CoreV1Api()
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            pods = corev1.list_namespaced_pod(namespace=NAMESPACE, field_selector=field_selector)
        except ApiException as e:
            logging.error(f"Error retrieving pods in namespace {NAMESPACE} with selector {field_selector}: {e}")
            return False

        if not pods.items:
            logging.warning(f"No pods found in namespace {NAMESPACE} matching field selector: {field_selector}")
        else:
            for pod in pods.items:
                if pod.status.phase == "Succeeded":
                    logging.info(f"Pod {pod.metadata.name} has successfully completed")
                    return True
                elif pod.status.phase in ["Failed", "Unknown"]:
                    logging.warning(f"Pod {pod.metadata.name} has failed or is in an unknown state: {pod.status.phase}")
                    return False

        logging.info("Matching pods are still running. Retrying...")
        time.sleep(2)

    logging.warning(
        f"Timeout reached: No pod matching {field_selector} completed successfully within {timeout} seconds"
    )
    return False


# simulates: $ oc logs -f <pod> | tee <file>
def tee_log(pod_name: str, filename: str, container: Optional[str] = None):
    corev1 = client.CoreV1Api()
    w = watch.Watch()
    kwargs = {"name": pod_name, "namespace": NAMESPACE}
    if container:
        kwargs["container"] = container
    with open(filename, "w", encoding="utf-8") as f:
        for e in w.stream(corev1.read_namespaced_pod_log, **kwargs):
            if not isinstance(e, str):
                continue  # Watch.stream() can yield non-string types
            f.write(e + "\n")
            print(e)


def render_manifests(input_dir, output_dir):
    shutil.copytree(input_dir, output_dir, dirs_exist_ok=True)
    logging.info(f"rendering manifests in {output_dir}")
    logging.info(f"using serviceaccount {SERVICEACCOUNT}")
    # XXX should probably replace this with something like kustomize
    for filepath in os.scandir(output_dir):
        with open(filepath, "r", encoding="utf-8") as f:
            contents = f.read()
        contents = contents.replace("${RAPIDAST_LLM_IMAGE}", RAPIDAST_LLM_IMAGE)
        contents = contents.replace("${IMAGE}", RAPIDAST_IMAGE)
        contents = contents.replace("${SERVICEACCOUNT}", SERVICEACCOUNT)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(contents)


def setup_namespace():
    global NAMESPACE  # pylint: disable=W0603
    # only try to create a namespace if env is set
    if NAMESPACE == "":
        NAMESPACE = get_current_namespace()
    else:
        create_namespace(NAMESPACE)
    logging.info(f"using namespace '{NAMESPACE}'")


def get_current_namespace() -> str:
    try:
        # Load the kubeconfig
        config.load_config()

        # Get the kube config object
        _, active_context = config.list_kube_config_contexts()

        # Return the namespace from current context
        if active_context and "namespace" in active_context["context"]:
            return active_context["context"]["namespace"]
        return "default"

    except config.config_exception.ConfigException:
        # If running inside a pod
        try:
            with open("/var/run/secrets/kubernetes.io/serviceaccount/namespace", "r", encoding="utf-8") as f:
                return f.read().strip()
        except FileNotFoundError:
            return "default"


def create_namespace(namespace_name: str):
    config.load_config()
    corev1 = client.CoreV1Api()
    try:
        corev1.read_namespace(namespace_name)
        logging.info(f"namespace {namespace_name} already exists")
    except ApiException as e:
        if e.status == 404:
            logging.info(f"creating namespace {namespace_name}")
            namespace = client.V1Namespace(metadata=client.V1ObjectMeta(name=namespace_name))
            corev1.create_namespace(namespace)
        else:
            raise e
    except Exception as e:  # pylint: disable=W0718
        logging.error(f"error reading namespace {namespace_name}: {e}")


def new_kclient():
    config.load_config()
    return client.ApiClient()


# XXX hook called by pytest-json-report plugin
def pytest_json_modifyreport(json_report: Dict):
    num_passed = json_report["summary"].get("passed", 0)
    num_failed = json_report["summary"].get("failed", 0)
    num_total = json_report["summary"]["total"]
    timestamp = str(int(json_report["created"] + json_report["duration"]))
    result = "ERROR"
    if num_passed == num_total:
        result = "SUCCESS"
    elif num_failed > 0:
        result = "FAILURE"
    json_report.clear()
    json_report["result"] = result
    json_report["timestamp"] = timestamp
    json_report["successes"] = num_passed
    json_report["failures"] = num_failed
    json_report["warnings"] = 0


class TestBase:
    _teardowns = []

    @classmethod
    def setup_class(cls):
        cls.tempdir = tempfile.mkdtemp()
        cls.kclient = new_kclient()
        render_manifests(MANIFESTS, cls.tempdir)
        logging.info(f"testing with image: {RAPIDAST_IMAGE}")
        setup_namespace()

    @classmethod
    def teardown_class(cls):
        # TODO teardown should really occur after each test, so the the
        # resource count does not grown until quota reached
        if RAPIDAST_CLEANUP:
            for func in cls._teardowns:
                logging.debug(f"calling {func}")
                func()

    def create_from_yaml(self, path: str):
        # delete resources in teardown method later
        self._teardowns.append(partial(os.system, f"kubectl delete -f {path} -n {NAMESPACE} --ignore-not-found"))
        o = utils.create_from_yaml(self.kclient, path, namespace=NAMESPACE, verbose=True)
        logging.debug(o)

    def replace_from_yaml(self, path: str):
        self._teardowns.append(partial(os.system, f"kubectl delete -f {path} -n {NAMESPACE} --ignore-not-found"))
        # We need to delete the existing resource and create a new one instead of replacing it,
        # because some resources, like pods, cannot be updated in place in Openshift due to SCC
        os.system(f"kubectl delete -f {path} -n {NAMESPACE} --ignore-not-found")
        os.system(f"kubectl apply -f {path} -n {NAMESPACE}")


@pytest.fixture
def _setup_teardown_for_oobkube():
    yield
    os.system(f"kubectl delete ConfigMap/vulnerable -n {NAMESPACE}")
