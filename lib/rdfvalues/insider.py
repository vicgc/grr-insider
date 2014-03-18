#!/usr/bin/env python
"""Values collected in the process of insider threat scanning."""

from grr.lib import rdfvalue
from grr.lib.rdfvalues import protodict

class InsiderStats(protodict.RDFValueArray):
  """An array of (currently dummy string) samples collected by bulk_extractor"""
  rdf_type = rdfvalue.RDFString
