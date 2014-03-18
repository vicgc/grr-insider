#!/usr/bin/env python
"""AFF4 objects for insider threat analysis"""

from grr.lib import aff4
from grr.lib import rdfvalue
from grr.lib.aff4_objects import collections

class InsiderStats(collections.AFF4Collection):
    """Stores disk statistics."""

    class SchemaCls(collections.AFF4Collection.SchemaCls):
        STATS = aff4.Attribute("aff4:insiderstats", rdfvalue.InsiderStats,
                "Insider threat disk statistics", "Statistics")
