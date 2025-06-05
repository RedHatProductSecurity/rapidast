import copy
import logging
from typing import Any
from typing import Dict
from typing import Optional

import celpy

from configmodel.models.false_positive_filtering import FalsePositiveFiltering

logger = logging.getLogger(f"{__name__}")


class CELFalsePositiveFilter:
    def __init__(self, config: FalsePositiveFiltering):
        self.config = config
        self.cel_env = celpy.Environment()
        self.compiled_cel_program = None

        if self.config.enabled:
            try:
                self.compiled_cel_program = self._compile_combined_cel_expression()
            except Exception as e:  # pylint: disable=W0718
                logger.warning(
                    f"Failed to compile CEL filter expressions. False positive filtering will be disabled. Error: {e}"
                )
                self.config.enabled = False

        # cel-python loggers are very verbose at the INFO level.
        # NOTE: As of version v0.3, loggers are created in the root namespace (e.g., "Evaluator", "Environment")
        # This has been improved in the main branch, where loggers are now properly namespaced under "celpy"
        # @TODO: Update logger configuration once the package is upgraded to a version that includes this fix
        for name in ["Evaluator", "Environment", "InterpretedRunner", "NameContainer", "evaluation", "celtypes"]:
            logging.getLogger(name).setLevel(logging.WARNING)

    def _compile_combined_cel_expression(self) -> Optional[celpy.Runner]:
        """
        Combines all CEL expressions from the rules and compiles them into a single program.
        """
        if not self.config.enabled or not self.config.rules:
            return None

        combined_cel_expression_parts = []
        for rule in self.config.rules:
            if rule.cel_expression:
                # Wrap each expression in parentheses for correct logical grouping
                combined_cel_expression_parts.append(f"({rule.cel_expression})")

        if not combined_cel_expression_parts:
            return None

        combined_cel_expression = " || ".join(combined_cel_expression_parts)

        logger.debug(f"Compiling combined CEL expression: {combined_cel_expression}")
        ast = self.cel_env.compile(combined_cel_expression)
        return self.cel_env.program(ast)

    def is_false_positive(self, sarif_result: Dict[str, Any]) -> bool:
        """
        Evaluates if a given SARIF result is a false positive based on the compiled CEL rules.

        Args:
            sarif_result: The individual SARIF result dictionary to evaluate.
            full_sarif_data: The entire SARIF file dictionary, for context if needed by rules.

        Returns:
            True if the result is a false positive and should be filtered out, False otherwise.
        """
        if not self.config.enabled or self.compiled_cel_program is None:
            return False

        try:
            activation = {
                "result": celpy.json_to_cel(sarif_result),
            }

            is_fp = self.compiled_cel_program.evaluate(activation)

            return bool(is_fp)
        except Exception as e:  # pylint: disable=W0718
            logger.warning(
                f"""
                Error evaluating CEL expression for result (ruleId: {sarif_result.get('ruleId', 'N/A')}): {e}.
                Treating as NOT a false positive
                """
            )
            return False

    def filter_sarif_results(self, sarif_data: Dict[str, Any]) -> Dict[str, Any]:
        if not self.config.enabled or not self.config.rules or self.compiled_cel_program is None:
            logger.info(
                """
                False positive filtering is disabled or no rules are
                configured/compiled. Returning original SARIF data
                """
            )
            return sarif_data

        filtered_sarif_data = copy.deepcopy(sarif_data)

        if not filtered_sarif_data.get("runs"):
            logger.warning("SARIF data has no 'runs' array. Nothing to filter. Returning original data.")
            return sarif_data

        total_original_results = 0
        total_filtered_results = 0

        for run_index, run in enumerate(filtered_sarif_data["runs"]):
            original_run_results = run.get("results", [])
            total_original_results += len(original_run_results)

            filtered_run_results = []

            logger.info(
                f"""
                Filtering results for run {run_index+1}/{len(filtered_sarif_data['runs'])}.
                Original results in this run: {len(original_run_results)}
                """
            )

            for sarif_result in original_run_results:
                if not self.is_false_positive(sarif_result):
                    filtered_run_results.append(sarif_result)
                else:
                    rule_id = sarif_result.get("ruleId", "N/A")
                    level = sarif_result.get("level", "N/A")
                    logger.debug(
                        f"Filtered out SARIF result in run {run_index+1}: Rule ID '{rule_id}', Level '{level}'"
                    )

            run["results"] = filtered_run_results
            total_filtered_results += len(filtered_run_results)

        logger.info(
            f"""
            False positive filtering complete. Total original results: {total_original_results}.
            Total filtered results: {total_filtered_results}
            """
        )
        return filtered_sarif_data
