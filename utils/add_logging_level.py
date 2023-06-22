import logging


# Inspired by: https://stackoverflow.com/a/35804945/1691778
def add_logging_level(level_name, level_num):
    """
    Precondition: The log level being added shouldn't already exist in the logging
    module
    """
    method_name = level_name.lower()

    def log_for_level(self, message, *args, **kwargs):
        if self.isEnabledFor(level_num):
            # pylint: disable=protected-access
            self._log(level_num, message, args, **kwargs)

    def log_to_root(message, *args, **kwargs):
        logging.log(level_num, message, *args, **kwargs)

    logging.addLevelName(level_num, level_name)
    setattr(logging, level_name, level_num)
    setattr(logging.getLoggerClass(), method_name, log_for_level)
    setattr(logging, method_name, log_to_root)
