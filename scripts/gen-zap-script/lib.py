import logging
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

import jinja2
import jinja2.sandbox

from zapv2 import ZAPv2


# Global Variables
logger = logging.Logger("GenZAPScriptLib")
logger.addHandler(logging.StreamHandler())


@dataclass
class Finding:
    name: str
    description: str
    risk: int
    confidence: int


#
# JS scripting
#


class Script(object):
    """
    Parent class of ZAP script.
    Currently we only consider Graal.js/JS. Doing the same for Zest is possible but would require some additional coding
    (and a way to know when to choose which engine).
    """

    name_prefix = "Rule_Gen_"

    def __init__(self, type=None, engine="Graal.js", description="Empty Description"):
        self._name = None
        self.type = type
        self.engine = engine
        self.description = description
        self.template_env = jinja2.sandbox.SandboxedEnvironment(
            loader=jinja2.ChoiceLoader(
                [
                    jinja2.FileSystemLoader(searchpath="./"),
                    jinja2.FileSystemLoader(searchpath=str(Path(__file__).parent)),
                ]
            )
        )
        self.template = None
        self.params = {}  # dict[Str, Any]

    @property
    def name(self) -> str:
        if self._name is None:
            self._name = f"{Script.name_prefix}{uuid.uuid4()}"
        return self._name

    @name.setter
    def name(self, value):
        if value and isinstance(value, str):
            self._name = value

    @property
    def code(self) -> str:
        return self.template.render(params=self.params) if self.template else ""


class PassiveScript(Script):
    def __init__(self, template_filename="template_script_passive.js", **kwargs):
        super().__init__(type="passive", **kwargs)
        self.template = self.template_env.get_template(template_filename)


class ActiveScript(Script):
    def __init__(self, template_filename="template_script_active.js", **kwargs):
        super().__init__(type="active", **kwargs)
        self.template = self.template_env.get_template(template_filename)


#
# Utils
#


def add_and_load_script(script: Script, **kwargs):
    zap = ZAPv2(**kwargs)
    logger.debug(f"Templating script {script.name}")
    with tempfile.NamedTemporaryFile(suffix=".js", prefix=script.name) as fp:
        fp.write(bytes(script.code, encoding="utf-8"))
        fp.seek(0)

        logger.debug(f"Loading script {script.name} in ZAP from {fp.name}")
        if (
            res := zap.script.load(
                script.name,
                script.type,
                script.engine,
                fp.name,
                script.description,
                apikey=kwargs["apikey"],
            )
        ) != "OK":
            raise RuntimeError(f"Attempting to load script returned an error: {res}")

    logger.debug(f"Enabling script {script.name} in ZAP")
    if (res := zap.script.enable(script.name, apikey=kwargs["apikey"])) != "OK":
        raise RuntimeError(f"Attempting to enable script returned an error: {res}")

    logger.info(f"Script {script.name} successfully loaded and enabled")


def delete_all_loaded_scripts(**kwargs):
    zap = ZAPv2(**kwargs)
    for name in [
        s["name"]
        for s in zap.script.list_scripts
        if s.get("name", "").startswith(Script.name_prefix)
    ]:
        logger.info(f"Removing script {name}")
        zap.script.remove(name, apikey=kwargs["apikey"])


__all__ = [
    "Finding",
    "ActiveScript",
    "PassiveScript",
    "add_and_load_script",
    "delete_all_loaded_scripts",
]
