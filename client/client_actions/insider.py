#!/usr/bin/env python
"""Support for statistical insider threat detection."""

from grr.client import actions
from grr.lib import rdfvalue
from grr.lib.rdfvalues.insider import InsiderStats
import bulkextractor
import json

class InsiderGather(actions.ActionPlugin):
  """Gather preselected filesystem statistics for later processing."""
  in_rdfvalue = None
  out_rdfvalue = InsiderStats

  def Run(self, unused_args):
    scanners = [ "email", "accts", "exif", "zip", "gzip", "rar", "bulk", ]
    bulkextractor.soft_init(scanners)
    be = bulkextractor.Session()
    be.analyze_buffer("Test Dataa  demo@bulk_extractor.org Just a demo 617-555-1212 ok!")
    be.finalize()
    res = InsiderStats(initializer=json.dumps(be.histograms()))
    self.SendReply(res)
