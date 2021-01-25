# serviceregistrator
#
# Copyright (C) 2021  MetaBrainz Foundation
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


class Service:

    def __init__(self, container_id, id_, name, ip, port, tags=None, attrs=None):
        #  https://github.com/gliderlabs/registrator/blob/4322fe00304d6de661865721b073dc5c7e750bd2/docs/user/services.md#service-object
        self.id = id_      # string               // unique service instance ID
        self.name = name   # string               // service name
        self.ip = ip       # string               // IP address service is located at
        self.port = port   # int                  // port service is listening on
        # []string             // extra tags to classify service
        self.tags = tags if not None else []
        #  map[string]string    // extra attribute metadata
        self.attrs = attrs if not None else dict()
        self.container_id = container_id

    def __str__(self):
        return '<{} (name:{} ip: {} port: {} tags: {}>'.format(
            self.id, self.name, self.ip, self.port, self.tags
        )

    def __repr__(self):
        return ("{t}('{s.container_id}', '{s.id}', '{s.name}', '{s.ip}', "
                "{s.port}, tags={s.tags}, attrs={s.attrs})").format(
            t=type(self).__name__,
            s=self)
