from collections import UserDict


class ContainerMetadata(UserDict):
    def __setitem__(self, key, value):
        # all keys are lowered
        key = key.lower()
        if key in ('tags', ):
            # handle lists merging
            if value is None:
                value = []
            elif not isinstance(value, list):
                value = list(set(value.split(',')))
            if key in self:
                # uniqify
                super().__setitem__(key, list(set(self[key] + value)))
            else:
                super().__setitem__(key, value)

        elif key in ('name', 'id'):
            # those keys are added as is
            super().__setitem__(key, value)
        elif key in ('attrs', ):
            # handle dict merging
            if key in self:
                self[key].update(value)
            else:
                super().__setitem__(key, value)
        else:
            # all other keys are added as attributes
            if 'attrs' not in self:
                super().__setitem__('attrs', dict())
            self['attrs'][key] = value

    def __repr__(self):
        return f"{type(self).__name__}({self.data})"
