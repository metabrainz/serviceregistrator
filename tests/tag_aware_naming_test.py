"""Tests for tag-aware multi-port naming (0.8.1 fix).

Same service name on two ports of one container:
  - different tag sets  -> both keep the shared name (tags disambiguate)
  - same tag set        -> port suffix applied (unchanged behaviour)
"""

import unittest

from serviceregistrator import ContainerMetadata, ServiceIP
from serviceregistrator.containerinfo import ContainerInfo
from serviceregistrator.registrator import Ports


def _ci(metadata_with_port):
    return ContainerInfo(
        "cid",
        "cont",
        [
            Ports(internal=3031, external=13060, protocol="tcp", ip="0.0.0.0"),
            Ports(internal=3032, external=13070, protocol="tcp", ip="0.0.0.0"),
        ],
        ContainerMetadata(),
        metadata_with_port,
        "host",
        [ServiceIP("10.2.2.23")],
        [],
    )


class TestTagAwareNaming(unittest.TestCase):
    def test_same_name_different_tags_keep_name(self):
        # picard-website case: uwsgi view + http view, same name, different tags
        ci = _ci(
            {
                3031: ContainerMetadata({"name": "picard-website", "tags": "beta,beta-uwsgi"}),
                3032: ContainerMetadata({"name": "picard-website", "tags": "beta,beta-http"}),
            }
        )
        names = sorted(s.name for s in ci.services)
        # both keep the bare name (no -13060 / -13070 suffix)
        assert names == ["picard-website", "picard-website"]
        # and they are distinct Consul services (unique IDs via port)
        ids = sorted(s.id for s in ci.services)
        assert ids == ["host:cont:13060", "host:cont:13070"]
        # tags distinguish them
        tagsets = sorted(sorted(s.tags) for s in ci.services)
        assert ["beta", "beta-http"] in tagsets
        assert ["beta", "beta-uwsgi"] in tagsets

    def test_same_name_same_tags_still_suffixed(self):
        # unchanged behaviour: identical name AND tags on two ports -> suffix
        ci = _ci(
            {
                3031: ContainerMetadata({"name": "dup", "tags": "prod"}),
                3032: ContainerMetadata({"name": "dup", "tags": "prod"}),
            }
        )
        names = sorted(s.name for s in ci.services)
        assert names == ["dup-13060", "dup-13070"]

    def test_same_name_no_tags_still_suffixed(self):
        # unchanged behaviour: identical name, no tags on two ports -> suffix
        ci = _ci(
            {
                3031: ContainerMetadata({"name": "dup"}),
                3032: ContainerMetadata({"name": "dup"}),
            }
        )
        names = sorted(s.name for s in ci.services)
        assert names == ["dup-13060", "dup-13070"]


if __name__ == "__main__":
    unittest.main()
