#!/usr/bin/env python
"""Support for statistical insider threat detection."""

from grr.client import actions
from grr.lib import rdfvalue

class InsiderGather(actions.ActionPlugin):
  """Gather preselected filesystem statistics for later processing."""
  in_rdfvalue = None
  out_rdfvalue = rdfvalue.RDFString

  def Run(self, unused_args):
    res = rdfvalue.RDFString(initializer="dry_run=True")
    self.SendReply(res)
