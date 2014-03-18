#!/usr/bin/env python

"""Flows for insider threat detection"""

from grr.lib import aff4
from grr.lib import flow


class InsiderInterrogate(flow.GRRFlow):
  """Collect a battery of statistics from a client."""

  category = "/Filesystem/Insider/"
  behaviours = flow.GRRFlow.behaviours + "BASIC"

  @flow.StateHandler(next_state=["StoreStats"])
  def Start(self):
    self.CallClient("InsiderGather", next_state="StoreStats")

  @flow.StateHandler()
  def StoreStats(self, responses):
    if not responses.success:
      raise flow.FlowError(str(responses.status))

    self.state.Register("urn", self.client_id.Add(
        "insider").Add("stats"))
    fd = aff4.FACTORY.Create(self.state.urn, "InsiderStats",
            token=self.token)
    if responses.success:
      stats = fd.Schema.STATS()
      for response in responses:
        stats.Append(response)
    else:
      raise flow.FlowError("bulk_extractor sampling failed. Err: {0}".format(
          responses.status))
    self.state.Register("stat_count", len(stats))

    fd.Set(stats)
    fd.Close()
