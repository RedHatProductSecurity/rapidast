###########################################################
# AUTHENTICATION HELPERS                                  #
# - authentication factory                                #
###########################################################


def generic_authentication_factory():
    """Decorator factory for generic authentication.
    First create the decorator:
        @generic_authentication_factory("zap")
        def authentication_factory(self):
            [ default action. i.e.: probably raise error]

    Then populate it by registering methods:
        @authentication_factory.register(None)
        def authentication_set_anonymous(self):
            [return authentication of type `None`]
    """

    def config_authentication_dispatcher(func):
        """This is intended to be a decorator to register authentication functions
        The function passed during creation will be called in case no suitable functions are found.
        i.e.: it should raise an error.

        It is possible to retrieve an authenticator by calling <dispatcher>.dispatch(<version>)
        This may be used for testing purpose
        """
        registry = {}  # "method" -> authenticator()

        registry["error"] = func

        def register(method):
            def inner(func):
                registry[method] = func
                return func

            return inner

        def decorator(scanner):
            authenticator = scanner.my_conf("authentication.type")
            func = registry.get(authenticator, registry["error"])
            return func(scanner)

        def dispatch(scanner):
            return registry.get(scanner, registry["error"])

        decorator.register = register
        decorator.registry = registry
        decorator.dispatch = dispatch

        return decorator

    return config_authentication_dispatcher
