import logging
import os
import pprint
import shutil
import subprocess

from .zap import MODULE_DIR
from .zap import Zap
from scanners import State
from scanners.downloaders import anonymous_download
from scanners.path_translators import make_mapping_for_scanner

CLASSNAME = "ZapNone"


pp = pprint.PrettyPrinter(indent=4)


class ZapNone(Zap):
    ###############################################################
    # PRIVATE CONSTANTS                                           #
    # Accessed by ZapLocalhost only                               #
    ###############################################################

    ###############################################################
    # PROTECTED CONSTANTS                                         #
    # Accessed by parent Zap object                               #
    ###############################################################

    def __init__(self, config):
        """Initialize all vars based on the config.
        The code of the function only deals with the "no container" layer, the "ZAP" layer is handled by super()
        """

        logging.debug("Initializing a local instance of the ZAP scanner")
        super().__init__(config)

        # Setup defaults specific to "no container" mode
        self.config.set(
            "scanners.zap.container.parameters.executable", "zap.sh", overwrite=False
        )

        # prepare the host <-> container mapping
        # Because there's no container layer, there's no need to translate anything
        temp_dir = self._create_temp_dir("workdir")

        # Generate on the fly a ZAP home dir, which will be filled up with default data.
        # The policies will be copied inside it.
        # Benefits: don't fiddle with user's ZAP environment, have a predictable base config
        self.zap_home = self._create_temp_dir("home")

        policies_dir = f"{self.zap_home}/policies"

        self.path_map = make_mapping_for_scanner(
            "Zap",
            ("workdir", temp_dir, temp_dir),
            ("scripts", f"{MODULE_DIR}/scripts", f"{MODULE_DIR}/scripts"),
            ("policies", policies_dir, policies_dir),
        )

    ###############################################################
    # PUBLIC METHODS                                              #
    # Accessed by RapiDAST                                        #
    # + MUST be implemented                                       #
    # + SHOUT call super().<method>                               #
    # + list: setup(), run(), postprocess(), cleanup()            #
    ###############################################################

    def setup(self):
        """Prepares everything:
        - the command line to run
        - environment variables
        - files & directory

        The code of the function only deals with the "no container" layer, the "ZAP" layer is handled by super()
        """

        if self.state != State.UNCONFIGURED:
            raise RuntimeError(f"ZAP setup encounter an unexpected state: {self.state}")

        super().setup()

        # Without a container layer, can't "mount" the policy directory, and ZAP does not allow changing it
        # We have to copy it to ZAP's policies directory
        if self.config.get("scanners.zap.activeScan", default=False) is not False:
            policy = self.config.get(
                "scanners.zap.activeScan.policy", default="API-scan-minimal"
            )
            os.mkdir(self.path_map.policies.host_path)
            self._include_file(
                host_path=f"{MODULE_DIR}/policies/{policy}.policy",
                dest_in_container=f"{self.path_map.policies.container_path}/{policy}.policy",
            )

        if self.state != State.ERROR:
            self.state = State.READY

    def run(self):
        """If the state is READY, run the final run command on the local machine
        There is no need to call super() here.
        """
        logging.info("Running up the ZAP scanner on the host")
        if not self.state == State.READY:
            raise RuntimeError("[ZAP SCANNER]: ERROR, not ready to run")

        self.check_plugin_status()

        # temporary workaround: cleanup addon state
        # see https://github.com/zaproxy/zaproxy/issues/7590#issuecomment-1308909500
        statefile = f"{self.zap_home}/add-ons-state.xml"
        try:
            os.remove(statefile)
        except FileNotFoundError:
            logging.info(f"The addon state file {statefile} was not created")

        if self.config.get("scanners.zap.miscOptions.updateAddons", default=True):
            logging.info("Zap: Updating addons")
            command = [
                self.config.get("scanners.zap.container.parameters.executable"),
                "-dir",
                self.zap_home,
                "-cmd",
                "-addonupdate",
            ]
            logging.debug(f"update command: {command}")
            result = subprocess.run(command, check=False)
            if result.returncode != 0:
                logging.warning(
                    f"The ZAP addon update process did not finish correctly, and exited with code {result.returncode}"
                )
            # temporary workaround: cleanup addon state
            # see https://github.com/zaproxy/zaproxy/issues/7590#issuecomment-1308909500
            statefile = f"{self.zap_home}/add-ons-state.xml"
            try:
                os.remove(statefile)
            except FileNotFoundError:
                logging.info(f"The addon state file {statefile} was not created")

        # Now the real run
        logging.info(f"Running ZAP with the following command:\n{self.zap_cli}")
        result = subprocess.run(self.zap_cli, check=False)
        logging.debug(
            f"ZAP returned the following:\n=====\n{pp.pformat(result)}\n====="
        )

        # Zap's return codes : https://www.zaproxy.org/docs/desktop/addons/automation-framework/
        if result.returncode in [0, 2]:
            # 0: ZAP returned correctly. 2: ZAP returned warning
            logging.info(
                f"The ZAP process finished with no errors, and exited with code {result.returncode}"
            )
            self.state = State.DONE
        else:
            # 1: Zap hit an error
            logging.warning(
                f"The ZAP process did not finish correctly, and exited with code {result.returncode}"
            )
            self.state = State.ERROR

    def postprocess(self):
        logging.info("Running postprocess for the ZAP Host environment")

        logging.debug(f"zap_home: {self.zap_home}")
        shutil.copy(
            f"{self.zap_home}/zap.log", f"{self._host_work_dir()}/{self.REPORTS_SUBDIR}"
        )

        super().postprocess()

        if not self.state == State.ERROR:
            self.state = State.PROCESSED

    def cleanup(self):
        logging.info("Running cleanup for the ZAP Host environment")

        if not self.state == State.PROCESSED:
            raise RuntimeError("No cleanning up as ZAP did not processed results.")

        logging.debug(
            f"Deleting temp directories {self._host_work_dir()} and {self.zap_home}"
        )
        shutil.rmtree(self._host_work_dir())
        shutil.rmtree(self.zap_home)

        super().cleanup()

        if not self.state == State.ERROR:
            self.state = State.CLEANEDUP

    ###############################################################
    # PROTECTED METHODS                                           #
    # Accessed by Zap parent only                                 #
    # + MUST be implemented                                       #
    ###############################################################

    def _setup_zap_cli(self):
        """
        Generate the main ZAP command line (not the container command).
        Uses super() to generate the generic part of the command
        """

        self.zap_cli = [
            self.config.get("scanners.zap.container.parameters.executable"),
            "-dir",
            self.zap_home,
        ]

        super()._setup_zap_cli()

        logging.debug(f"ZAP will run with: {self.zap_cli}")

    def _add_env(self, key, value=None):
        """Environment variable to be added to the container.
        If value is None, then the value should be taken from the current host

        In "no container" type, simply add the environment in the python process
        It will be copied over to ZAP.
        If `value` is None, then do nothing, as it means it's already set in
        python's environment
        """
        if value is not None:
            os.environ[key] = value

    ###############################################################
    # PRIVATE   METHODS                                           #
    # Accessed by ZapNone only                                    #
    # + MUST be implemented                                       #
    ###############################################################

    def check_plugin_status(self):
        """MacOS workaround for "The mandatory add-on was not found" error
        See https://github.com/zaproxy/zaproxy/issues/7703
        """
        logging.info("Zap: verifying the viability of ZAP")
        command = [
            self.config.get("scanners.zap.container.parameters.executable"),
            "-dir",
            self.zap_home,
            "-cmd",
        ]
        logging.debug(f"ZAP create home command: {command}")
        result = subprocess.run(command, check=False, capture_output=True)
        if result.returncode == 0:
            logging.debug("ZAP appears to be in a correct state")
        elif (
            result.stderr.find(bytes("The mandatory add-on was not found:", "ascii"))
            > 0
        ):
            logging.info("Missing mandatory plugins. Fixing")
            url_root = "https://github.com/zaproxy/zap-extensions/releases/download"
            anonymous_download(
                url=f"{url_root}/callhome-v0.6.0/callhome-release-0.6.0.zap",
                dest=f"{self.zap_home}/plugin/callhome-release-0.6.0.zap",
                proxy=self.config.get("scanners.zap.proxy", default=None),
            )
            anonymous_download(
                url=f"{url_root}/network-v0.9.0/network-beta-0.9.0.zap",
                dest=f"{self.zap_home}/plugin/network-beta-0.9.0.zap",
                proxy=self.config.get("scanners.zap.proxy", default=None),
            )
            logging.info("Workaround: installing all addons")
            command = [
                self.config.get("scanners.zap.container.parameters.executable"),
                "-dir",
                self.zap_home,
                "-cmd",
                "-addoninstallall",
            ]
            logging.debug(f"ZAP: installing all addons: {command}")
            result = subprocess.run(command, check=False)

        else:
            logging.warning(
                f"ZAP appears to be in a incorrect state. Error: {result.stderr}"
            )
