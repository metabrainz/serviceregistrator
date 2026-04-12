#  ServiceRegistrator is a service registry bridge between Docker and Consul
#
#    It is a stripped-down Python re-implementation of Gliderlabs Registrator,
#    partly compatible with its SERVICE_* syntax.
#
#    Copyright (C) 2021 Laurent Monin
#    Copyright (C) 2021 MetaBrainz Foundation
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.


class Service:
    def __init__(
        self,
        container_id: str,
        id_: str,
        name: str,
        ip: str,
        port: int,
        tags: list[str] | None = None,
        attrs: dict[str, str] | None = None,
        alias_of: str | None = None,
    ) -> None:
        self.id = id_
        self.name = name
        self.ip = ip
        self.port = port
        self.tags = tags if tags is not None else []
        self.attrs = attrs if attrs is not None else dict()
        self.container_id = container_id
        self.alias_of = alias_of

    def __str__(self) -> str:
        return (
            f"<{self.__class__.__name__}: {self.id} (name:{self.name} ip:{self.ip} port:{self.port} tags:{self.tags}>"
        )

    def __repr__(self) -> str:
        return (
            "{t}('{s.container_id}', '{s.id}', '{s.name}', '{s.ip}', {s.port}, tags={s.tags}, attrs={s.attrs})"
        ).format(t=type(self).__name__, s=self)
