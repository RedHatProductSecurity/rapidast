from utils.query import Query


class Parser(Query):
    _q = None

    @property
    def q(self):
        if not self._q:
            self._q = self._build_query(self.data)
        return self._q
