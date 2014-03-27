#!/usr/bin/env python
"""Values collected in the process of insider threat scanning."""

from grr.lib import rdfvalue

class InsiderStats(rdfvalue.RDFString):
  """
  A JSON serialized key-value set of statistics relevant to insider
  investigation.
  """
  pass
