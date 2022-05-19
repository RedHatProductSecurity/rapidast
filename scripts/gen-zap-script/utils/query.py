class Query:
    @staticmethod
    def _build_query(data):
        """Build query object from data.

        data: may be any python structure

        Return:
            an instance of `Item` class
        """

        def walk_data(data):
            children = []
            if isinstance(data, dict):
                for key, value in data.items():
                    if value and isinstance(value, (dict, list)):
                        children.append(Item(name=key, children=walk_data(value)))
                    else:
                        children.append(Item(name=key, value=value))
            elif isinstance(data, list):
                for value in data:
                    if value and isinstance(value, (dict, list)):
                        children.append(Item(children=walk_data(value)))
                    else:
                        children.append(Item(value=value))
            else:
                children.append(Item(value=data))
            return children

        return Item(children=walk_data(data))


class Item:
    """A class which represents a node of the query object."""

    def __init__(self, name=None, children=None, value=None):
        self._name = name
        self._children = children
        self._value = value

    def __getattr__(self, attr_name):
        if self.children:
            for child in self.children:
                if isinstance(child, Item):
                    if child.name == attr_name:
                        return child
                if isinstance(child, list):
                    return child

        return Item()

    def __getitem__(self, index):
        if isinstance(index, int) and self.children and len(self.children) >= index:
            return self.children[index]
        if isinstance(index, str):
            return getattr(self, index)
        return Item()

    @property
    def children(self):
        return self._children

    @property
    def name(self):
        return self._name

    @property
    def value(self):
        if self.children and isinstance(self.children, list):
            value_list = [i.value for i in self.children]
            return value_list
        return self._value

    def find(self):
        pass

    def filter(self):
        pass

    def where(self):
        pass

    def to_dict(self):
        pass
